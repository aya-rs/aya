//! Object file loading, parsing, and relocation.

use alloc::{
    borrow::ToOwned,
    collections::BTreeMap,
    ffi::CString,
    string::{String, ToString},
    vec::Vec,
};
use core::{ffi::CStr, mem, ptr, slice::from_raw_parts_mut, str::FromStr};

use log::debug;
use object::{
    read::{Object as ElfObject, ObjectSection, Section as ObjSection},
    Endianness, ObjectSymbol, ObjectSymbolTable, RelocationTarget, SectionIndex, SectionKind,
    SymbolKind,
};

#[cfg(not(feature = "std"))]
use crate::std;
use crate::{
    btf::{
        Array, Btf, BtfError, BtfExt, BtfFeatures, BtfType, DataSecEntry, FuncSecInfo, LineSecInfo,
    },
    generated::{
        bpf_insn, bpf_map_info, bpf_map_type::BPF_MAP_TYPE_ARRAY, BPF_CALL, BPF_F_RDONLY_PROG,
        BPF_JMP, BPF_K,
    },
    maps::{bpf_map_def, BtfMap, BtfMapDef, LegacyMap, Map, PinningType, MINIMUM_MAP_SIZE},
    programs::{
        CgroupSockAddrAttachType, CgroupSockAttachType, CgroupSockoptAttachType, XdpAttachType,
    },
    relocation::*,
    util::HashMap,
};

const KERNEL_VERSION_ANY: u32 = 0xFFFF_FFFE;

/// Features implements BPF and BTF feature detection
#[derive(Default, Debug)]
#[allow(missing_docs)]
pub struct Features {
    bpf_name: bool,
    bpf_probe_read_kernel: bool,
    bpf_perf_link: bool,
    bpf_global_data: bool,
    bpf_cookie: bool,
    cpumap_prog_id: bool,
    devmap_prog_id: bool,
    prog_info_map_ids: bool,
    prog_info_gpl_compatible: bool,
    btf: Option<BtfFeatures>,
}

impl Features {
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bpf_name: bool,
        bpf_probe_read_kernel: bool,
        bpf_perf_link: bool,
        bpf_global_data: bool,
        bpf_cookie: bool,
        cpumap_prog_id: bool,
        devmap_prog_id: bool,
        prog_info_map_ids: bool,
        prog_info_gpl_compatible: bool,
        btf: Option<BtfFeatures>,
    ) -> Self {
        Self {
            bpf_name,
            bpf_probe_read_kernel,
            bpf_perf_link,
            bpf_global_data,
            bpf_cookie,
            cpumap_prog_id,
            devmap_prog_id,
            prog_info_map_ids,
            prog_info_gpl_compatible,
            btf,
        }
    }

    /// Returns whether BPF program names and map names are supported.
    ///
    /// Although the feature probe performs the check for program name, we can use this to also
    /// detect if map name is supported since they were both introduced in the same commit.
    pub fn bpf_name(&self) -> bool {
        self.bpf_name
    }

    /// Returns whether the bpf_probe_read_kernel helper is supported.
    pub fn bpf_probe_read_kernel(&self) -> bool {
        self.bpf_probe_read_kernel
    }

    /// Returns whether bpf_links are supported for Kprobes/Uprobes/Tracepoints.
    pub fn bpf_perf_link(&self) -> bool {
        self.bpf_perf_link
    }

    /// Returns whether BPF program global data is supported.
    pub fn bpf_global_data(&self) -> bool {
        self.bpf_global_data
    }

    /// Returns whether BPF program cookie is supported.
    pub fn bpf_cookie(&self) -> bool {
        self.bpf_cookie
    }

    /// Returns whether XDP CPU Maps support chained program IDs.
    pub fn cpumap_prog_id(&self) -> bool {
        self.cpumap_prog_id
    }

    /// Returns whether XDP Device Maps support chained program IDs.
    pub fn devmap_prog_id(&self) -> bool {
        self.devmap_prog_id
    }

    /// Returns whether `bpf_prog_info` supports `nr_map_ids` & `map_ids` fields.
    pub fn prog_info_map_ids(&self) -> bool {
        self.prog_info_map_ids
    }

    /// Returns whether `bpf_prog_info` supports `gpl_compatible` field.
    pub fn prog_info_gpl_compatible(&self) -> bool {
        self.prog_info_gpl_compatible
    }

    /// If BTF is supported, returns which BTF features are supported.
    pub fn btf(&self) -> Option<&BtfFeatures> {
        self.btf.as_ref()
    }
}

/// The loaded object file representation
#[derive(Clone, Debug)]
pub struct Object {
    /// The endianness
    pub endianness: Endianness,
    /// Program license
    pub license: CString,
    /// Kernel version
    pub kernel_version: Option<u32>,
    /// Program BTF
    pub btf: Option<Btf>,
    /// Program BTF.ext
    pub btf_ext: Option<BtfExt>,
    /// Referenced maps
    pub maps: HashMap<String, Map>,
    /// A hash map of programs, using the program names parsed
    /// in [ProgramSection]s as keys.
    pub programs: HashMap<String, Program>,
    /// Functions
    pub functions: BTreeMap<(usize, u64), Function>,
    pub(crate) relocations: HashMap<SectionIndex, HashMap<u64, Relocation>>,
    pub(crate) symbol_table: HashMap<usize, Symbol>,
    pub(crate) symbols_by_section: HashMap<SectionIndex, Vec<usize>>,
    pub(crate) section_infos: HashMap<String, (SectionIndex, u64)>,
    // symbol_offset_by_name caches symbols that could be referenced from a
    // BTF VAR type so the offsets can be fixed up
    pub(crate) symbol_offset_by_name: HashMap<String, u64>,
}

/// An eBPF program
#[derive(Debug, Clone)]
pub struct Program {
    /// The license
    pub license: CString,
    /// The kernel version
    pub kernel_version: Option<u32>,
    /// The section containing the program
    pub section: ProgramSection,
    /// The section index of the program
    pub section_index: usize,
    /// The address of the program
    pub address: u64,
}

impl Program {
    /// The key used by [Object::functions]
    pub fn function_key(&self) -> (usize, u64) {
        (self.section_index, self.address)
    }
}

/// An eBPF function
#[derive(Debug, Clone)]
pub struct Function {
    /// The address
    pub address: u64,
    /// The function name
    pub name: String,
    /// The section index
    pub section_index: SectionIndex,
    /// The section offset
    pub section_offset: usize,
    /// The eBPF byte code instructions
    pub instructions: Vec<bpf_insn>,
    /// The function info
    pub func_info: FuncSecInfo,
    /// The line info
    pub line_info: LineSecInfo,
    /// Function info record size
    pub func_info_rec_size: usize,
    /// Line info record size
    pub line_info_rec_size: usize,
}

/// Section types containing eBPF programs
///
/// # Section Name Parsing
///
/// Section types are parsed from the section name strings.
///
/// In order for Aya to treat a section as a [ProgramSection],
/// there are a few requirements:
/// - The section must be an executable code section.
/// - The section name must conform to [Program Types and ELF Sections].
///
/// [Program Types and ELF Sections]: https://docs.kernel.org/bpf/libbpf/program_types.html
///
/// # Unsupported Sections
///
/// Currently, the following section names are not supported yet:
/// - `flow_dissector`: `BPF_PROG_TYPE_FLOW_DISSECTOR`
/// - `ksyscall+` or `kretsyscall+`
/// - `usdt+`
/// - `kprobe.multi+` or `kretprobe.multi+`: `BPF_TRACE_KPROBE_MULTI`
/// - `lsm_cgroup+`
/// - `lwt_in`, `lwt_out`, `lwt_seg6local`, `lwt_xmit`
/// - `raw_tp.w+`, `raw_tracepoint.w+`
/// - `action`
/// - `sk_reuseport/migrate`, `sk_reuseport`
/// - `syscall`
/// - `struct_ops+`
/// - `fmod_ret+`, `fmod_ret.s+`
/// - `iter+`, `iter.s+`
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub enum ProgramSection {
    KRetProbe,
    KProbe,
    UProbe {
        sleepable: bool,
    },
    URetProbe {
        sleepable: bool,
    },
    TracePoint {
        category: Option<String>,
        name: Option<String>,
    },
    SocketFilter,
    Xdp {
        frags: bool,
        attach_type: XdpAttachType,
    },
    SkMsg,
    SkSkbStreamParser,
    SkSkbStreamVerdict,
    SockOps,
    SchedClassifier,
    CgroupSkb,
    CgroupSkbIngress,
    CgroupSkbEgress,
    CgroupSockAddr {
        attach_type: CgroupSockAddrAttachType,
    },
    CgroupSysctl,
    CgroupSockopt {
        attach_type: CgroupSockoptAttachType,
    },
    LircMode2,
    PerfEvent,
    RawTracePoint,
    Lsm {
        sleepable: bool,
    },
    BtfTracePoint,
    FEntry {
        sleepable: bool,
    },
    FExit {
        sleepable: bool,
    },
    Extension,
    SkLookup,
    CgroupSock {
        attach_type: CgroupSockAttachType,
    },
    CgroupDevice,
}

impl FromStr for ProgramSection {
    type Err = ParseError;

    fn from_str(section: &str) -> Result<ProgramSection, ParseError> {
        use ProgramSection::*;

        // parse the common case, eg "xdp/program_name" or
        // "sk_skb/stream_verdict/program_name"
        let mut pieces = section.split('/');
        let mut next = || {
            pieces
                .next()
                .ok_or_else(|| ParseError::InvalidProgramSection {
                    section: section.to_owned(),
                })
        };
        let kind = next()?;

        Ok(match kind {
            "kprobe" => KProbe,
            "kretprobe" => KRetProbe,
            "uprobe" => UProbe { sleepable: false },
            "uprobe.s" => UProbe { sleepable: true },
            "uretprobe" => URetProbe { sleepable: false },
            "uretprobe.s" => URetProbe { sleepable: true },
            "xdp" | "xdp.frags" => Xdp {
                frags: kind == "xdp.frags",
                attach_type: match pieces.next() {
                    None => XdpAttachType::Interface,
                    Some("cpumap") => XdpAttachType::CpuMap,
                    Some("devmap") => XdpAttachType::DevMap,
                    Some(_) => {
                        return Err(ParseError::InvalidProgramSection {
                            section: section.to_owned(),
                        })
                    }
                },
            },
            "tp_btf" => BtfTracePoint,
            "tracepoint" | "tp" => {
                let category = pieces.next().map(|s| s.to_string());
                let name = pieces.next().map(|s| s.to_string());
                TracePoint { category, name }
            }
            "socket" => SocketFilter,
            "sk_msg" => SkMsg,
            "sk_skb" => {
                let name = next()?;
                match name {
                    "stream_parser" => SkSkbStreamParser,
                    "stream_verdict" => SkSkbStreamVerdict,
                    _ => {
                        return Err(ParseError::InvalidProgramSection {
                            section: section.to_owned(),
                        })
                    }
                }
            }
            "sockops" => SockOps,
            "classifier" => SchedClassifier,
            "cgroup_skb" => {
                let name = next()?;
                match name {
                    "ingress" => CgroupSkbIngress,
                    "egress" => CgroupSkbEgress,
                    _ => {
                        return Err(ParseError::InvalidProgramSection {
                            section: section.to_owned(),
                        })
                    }
                }
            }
            "cgroup" => {
                let name = next()?;
                match name {
                    "skb" => CgroupSkb,
                    "sysctl" => CgroupSysctl,
                    "dev" => CgroupDevice,
                    "getsockopt" => CgroupSockopt {
                        attach_type: CgroupSockoptAttachType::Get,
                    },
                    "setsockopt" => CgroupSockopt {
                        attach_type: CgroupSockoptAttachType::Set,
                    },
                    "sock" => CgroupSock {
                        attach_type: CgroupSockAttachType::default(),
                    },
                    "post_bind4" => CgroupSock {
                        attach_type: CgroupSockAttachType::PostBind4,
                    },
                    "post_bind6" => CgroupSock {
                        attach_type: CgroupSockAttachType::PostBind6,
                    },
                    "sock_create" => CgroupSock {
                        attach_type: CgroupSockAttachType::SockCreate,
                    },
                    "sock_release" => CgroupSock {
                        attach_type: CgroupSockAttachType::SockRelease,
                    },
                    "bind4" => CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::Bind4,
                    },
                    "bind6" => CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::Bind6,
                    },
                    "connect4" => CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::Connect4,
                    },
                    "connect6" => CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::Connect6,
                    },
                    "getpeername4" => CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::GetPeerName4,
                    },
                    "getpeername6" => CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::GetPeerName6,
                    },
                    "getsockname4" => CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::GetSockName4,
                    },
                    "getsockname6" => CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::GetSockName6,
                    },
                    "sendmsg4" => CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::UDPSendMsg4,
                    },
                    "sendmsg6" => CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::UDPSendMsg6,
                    },
                    "recvmsg4" => CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::UDPRecvMsg4,
                    },
                    "recvmsg6" => CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::UDPRecvMsg6,
                    },
                    _ => {
                        return Err(ParseError::InvalidProgramSection {
                            section: section.to_owned(),
                        });
                    }
                }
            }
            "lirc_mode2" => LircMode2,
            "perf_event" => PerfEvent,
            "raw_tp" | "raw_tracepoint" => RawTracePoint,
            "lsm" => Lsm { sleepable: false },
            "lsm.s" => Lsm { sleepable: true },
            "fentry" => FEntry { sleepable: false },
            "fentry.s" => FEntry { sleepable: true },
            "fexit" => FExit { sleepable: false },
            "fexit.s" => FExit { sleepable: true },
            "freplace" => Extension,
            "sk_lookup" => SkLookup,
            _ => {
                return Err(ParseError::InvalidProgramSection {
                    section: section.to_owned(),
                })
            }
        })
    }
}

impl Object {
    /// Parses the binary data as an object file into an [Object]
    pub fn parse(data: &[u8]) -> Result<Object, ParseError> {
        let obj = object::read::File::parse(data).map_err(ParseError::ElfError)?;
        let endianness = obj.endianness();

        let license = if let Some(section) = obj.section_by_name("license") {
            parse_license(Section::try_from(&section)?.data)?
        } else {
            CString::new("GPL").unwrap()
        };

        let kernel_version = if let Some(section) = obj.section_by_name("version") {
            parse_version(Section::try_from(&section)?.data, endianness)?
        } else {
            None
        };

        let mut bpf_obj = Object::new(endianness, license, kernel_version);

        if let Some(symbol_table) = obj.symbol_table() {
            for symbol in symbol_table.symbols() {
                let name = symbol
                    .name()
                    .ok()
                    .map(String::from)
                    .ok_or(BtfError::InvalidSymbolName)?;
                let sym = Symbol {
                    index: symbol.index().0,
                    name: Some(name.clone()),
                    section_index: symbol.section().index().map(|i| i.0),
                    address: symbol.address(),
                    size: symbol.size(),
                    is_definition: symbol.is_definition(),
                    kind: symbol.kind(),
                };
                bpf_obj.symbol_table.insert(symbol.index().0, sym);
                if let Some(section_idx) = symbol.section().index() {
                    bpf_obj
                        .symbols_by_section
                        .entry(section_idx)
                        .or_default()
                        .push(symbol.index().0);
                }
                if symbol.is_global() || symbol.kind() == SymbolKind::Data {
                    bpf_obj.symbol_offset_by_name.insert(name, symbol.address());
                }
            }
        }

        // .BTF and .BTF.ext sections must be parsed first
        // as they're required to prepare function and line information
        // when parsing program sections
        if let Some(s) = obj.section_by_name(".BTF") {
            bpf_obj.parse_section(Section::try_from(&s)?)?;
            if let Some(s) = obj.section_by_name(".BTF.ext") {
                bpf_obj.parse_section(Section::try_from(&s)?)?;
            }
        }

        for s in obj.sections() {
            if let Ok(name) = s.name() {
                if name == ".BTF" || name == ".BTF.ext" {
                    continue;
                }
            }

            bpf_obj.parse_section(Section::try_from(&s)?)?;
        }

        Ok(bpf_obj)
    }

    fn new(endianness: Endianness, license: CString, kernel_version: Option<u32>) -> Object {
        Object {
            endianness,
            license,
            kernel_version,
            btf: None,
            btf_ext: None,
            maps: HashMap::new(),
            programs: HashMap::new(),
            functions: BTreeMap::new(),
            relocations: HashMap::new(),
            symbol_table: HashMap::new(),
            symbols_by_section: HashMap::new(),
            section_infos: HashMap::new(),
            symbol_offset_by_name: HashMap::new(),
        }
    }

    /// Patches map data
    pub fn patch_map_data(
        &mut self,
        globals: HashMap<&str, (&[u8], bool)>,
    ) -> Result<(), ParseError> {
        let symbols: HashMap<String, &Symbol> = self
            .symbol_table
            .iter()
            .filter(|(_, s)| s.name.is_some())
            .map(|(_, s)| (s.name.as_ref().unwrap().clone(), s))
            .collect();

        for (name, (data, must_exist)) in globals {
            if let Some(symbol) = symbols.get(name) {
                if data.len() as u64 != symbol.size {
                    return Err(ParseError::InvalidGlobalData {
                        name: name.to_string(),
                        sym_size: symbol.size,
                        data_size: data.len(),
                    });
                }
                let (_, map) = self
                    .maps
                    .iter_mut()
                    // assumption: there is only one map created per section where we're trying to
                    // patch data. this assumption holds true for the .rodata section at least
                    .find(|(_, m)| symbol.section_index == Some(m.section_index()))
                    .ok_or_else(|| ParseError::MapNotFound {
                        index: symbol.section_index.unwrap_or(0),
                    })?;
                let start = symbol.address as usize;
                let end = start + symbol.size as usize;
                if start > end || end > map.data().len() {
                    return Err(ParseError::InvalidGlobalData {
                        name: name.to_string(),
                        sym_size: symbol.size,
                        data_size: data.len(),
                    });
                }
                map.data_mut().splice(start..end, data.iter().cloned());
            } else if must_exist {
                return Err(ParseError::SymbolNotFound {
                    name: name.to_owned(),
                });
            }
        }
        Ok(())
    }

    fn parse_btf(&mut self, section: &Section) -> Result<(), BtfError> {
        self.btf = Some(Btf::parse(section.data, self.endianness)?);

        Ok(())
    }

    fn parse_btf_ext(&mut self, section: &Section) -> Result<(), BtfError> {
        self.btf_ext = Some(BtfExt::parse(
            section.data,
            self.endianness,
            self.btf.as_ref().unwrap(),
        )?);
        Ok(())
    }

    fn parse_programs(&mut self, section: &Section) -> Result<(), ParseError> {
        let program_section = ProgramSection::from_str(section.name)?;
        let syms =
            self.symbols_by_section
                .get(&section.index)
                .ok_or(ParseError::NoSymbolsForSection {
                    section_name: section.name.to_string(),
                })?;
        for symbol_index in syms {
            let symbol = self
                .symbol_table
                .get(symbol_index)
                .expect("all symbols in symbols_by_section are also in symbol_table");

            // Here we get both ::Label (LBB*) and ::Text symbols, and we only want the latter.
            let name = match (symbol.name.as_ref(), symbol.kind) {
                (Some(name), SymbolKind::Text) if !name.is_empty() => name,
                _ => continue,
            };

            let (p, f) =
                self.parse_program(section, program_section.clone(), name.to_string(), symbol)?;
            let key = p.function_key();
            self.programs.insert(f.name.clone(), p);
            self.functions.insert(key, f);
        }
        Ok(())
    }

    fn parse_program(
        &self,
        section: &Section,
        program_section: ProgramSection,
        name: String,
        symbol: &Symbol,
    ) -> Result<(Program, Function), ParseError> {
        let offset = symbol.address as usize - section.address as usize;
        let (func_info, line_info, func_info_rec_size, line_info_rec_size) =
            get_func_and_line_info(self.btf_ext.as_ref(), symbol, section, offset, true);

        let start = symbol.address as usize;
        let end = (symbol.address + symbol.size) as usize;

        let function = Function {
            name: name.to_owned(),
            address: symbol.address,
            section_index: section.index,
            section_offset: start,
            instructions: copy_instructions(&section.data[start..end])?,
            func_info,
            line_info,
            func_info_rec_size,
            line_info_rec_size,
        };

        Ok((
            Program {
                license: self.license.clone(),
                kernel_version: self.kernel_version,
                section: program_section.clone(),
                section_index: section.index.0,
                address: symbol.address,
            },
            function,
        ))
    }

    fn parse_text_section(&mut self, section: Section) -> Result<(), ParseError> {
        let mut symbols_by_address = HashMap::new();

        for sym in self.symbol_table.values() {
            if sym.is_definition
                && sym.kind == SymbolKind::Text
                && sym.section_index == Some(section.index.0)
            {
                if symbols_by_address.contains_key(&sym.address) {
                    return Err(ParseError::SymbolTableConflict {
                        section_index: section.index.0,
                        address: sym.address,
                    });
                }
                symbols_by_address.insert(sym.address, sym);
            }
        }

        let mut offset = 0;
        while offset < section.data.len() {
            let address = section.address + offset as u64;
            let sym = symbols_by_address
                .get(&address)
                .ok_or(ParseError::UnknownSymbol {
                    section_index: section.index.0,
                    address,
                })?;
            if sym.size == 0 {
                return Err(ParseError::InvalidSymbol {
                    index: sym.index,
                    name: sym.name.clone(),
                });
            }

            let (func_info, line_info, func_info_rec_size, line_info_rec_size) =
                get_func_and_line_info(self.btf_ext.as_ref(), sym, &section, offset, false);

            self.functions.insert(
                (section.index.0, sym.address),
                Function {
                    address,
                    name: sym.name.clone().unwrap(),
                    section_index: section.index,
                    section_offset: offset,
                    instructions: copy_instructions(
                        &section.data[offset..offset + sym.size as usize],
                    )?,
                    func_info,
                    line_info,
                    func_info_rec_size,
                    line_info_rec_size,
                },
            );

            offset += sym.size as usize;
        }

        if !section.relocations.is_empty() {
            self.relocations.insert(
                section.index,
                section
                    .relocations
                    .into_iter()
                    .map(|rel| (rel.offset, rel))
                    .collect(),
            );
        }

        Ok(())
    }

    fn parse_btf_maps(&mut self, section: &Section) -> Result<(), ParseError> {
        if self.btf.is_none() {
            return Err(ParseError::NoBTF);
        }
        let btf = self.btf.as_ref().unwrap();
        let maps: HashMap<&String, usize> = self
            .symbols_by_section
            .get(&section.index)
            .ok_or(ParseError::NoSymbolsForSection {
                section_name: section.name.to_owned(),
            })?
            .iter()
            .filter_map(|s| {
                let symbol = self.symbol_table.get(s).unwrap();
                symbol.name.as_ref().map(|name| (name, symbol.index))
            })
            .collect();

        for t in btf.types() {
            if let BtfType::DataSec(datasec) = &t {
                let type_name = match btf.type_name(t) {
                    Ok(name) => name,
                    _ => continue,
                };
                if type_name == section.name {
                    // each btf_var_secinfo contains a map
                    for info in &datasec.entries {
                        let (map_name, def) = parse_btf_map_def(btf, info)?;
                        let symbol_index =
                            maps.get(&map_name)
                                .ok_or_else(|| ParseError::SymbolNotFound {
                                    name: map_name.to_string(),
                                })?;
                        self.maps.insert(
                            map_name,
                            Map::Btf(BtfMap {
                                def,
                                section_index: section.index.0,
                                symbol_index: *symbol_index,
                                data: Vec::new(),
                            }),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    // Parses multiple map definition contained in a single `maps` section (which is
    // different from `.maps` which is used for BTF). We can tell where each map is
    // based on the symbol table.
    fn parse_maps_section<'a, I: Iterator<Item = &'a usize>>(
        &self,
        maps: &mut HashMap<String, Map>,
        section: &Section,
        symbols: I,
    ) -> Result<(), ParseError> {
        let mut have_symbols = false;
        // each symbol in the section is a separate map
        for i in symbols {
            let sym = self.symbol_table.get(i).ok_or(ParseError::SymbolNotFound {
                name: i.to_string(),
            })?;
            let start = sym.address as usize;
            let end = start + sym.size as usize;
            let data = &section.data[start..end];
            let name = sym
                .name
                .as_ref()
                .ok_or(ParseError::MapSymbolNameNotFound { i: *i })?;
            let def = parse_map_def(name, data)?;
            maps.insert(
                name.to_string(),
                Map::Legacy(LegacyMap {
                    section_index: section.index.0,
                    section_kind: section.kind,
                    symbol_index: Some(sym.index),
                    def,
                    data: Vec::new(),
                }),
            );
            have_symbols = true;
        }
        if !have_symbols {
            return Err(ParseError::NoSymbolsForSection {
                section_name: section.name.to_owned(),
            });
        }

        Ok(())
    }

    fn parse_section(&mut self, section: Section) -> Result<(), ParseError> {
        self.section_infos
            .insert(section.name.to_owned(), (section.index, section.size));
        match section.kind {
            EbpfSectionKind::Data | EbpfSectionKind::Rodata | EbpfSectionKind::Bss => {
                self.maps
                    .insert(section.name.to_string(), parse_data_map_section(&section)?);
            }
            EbpfSectionKind::Text => self.parse_text_section(section)?,
            EbpfSectionKind::Btf => self.parse_btf(&section)?,
            EbpfSectionKind::BtfExt => self.parse_btf_ext(&section)?,
            EbpfSectionKind::BtfMaps => self.parse_btf_maps(&section)?,
            EbpfSectionKind::Maps => {
                // take out self.maps so we can borrow the iterator below
                // without cloning or collecting
                let mut maps = mem::take(&mut self.maps);

                // extract the symbols for the .maps section, we'll need them
                // during parsing
                let symbols = self
                    .symbols_by_section
                    .get(&section.index)
                    .ok_or(ParseError::NoSymbolsForSection {
                        section_name: section.name.to_owned(),
                    })?
                    .iter();

                let res = self.parse_maps_section(&mut maps, &section, symbols);

                // put the maps back
                self.maps = maps;

                res?
            }
            EbpfSectionKind::Program => {
                self.parse_programs(&section)?;
                if !section.relocations.is_empty() {
                    self.relocations.insert(
                        section.index,
                        section
                            .relocations
                            .into_iter()
                            .map(|rel| (rel.offset, rel))
                            .collect(),
                    );
                }
            }
            EbpfSectionKind::Undefined | EbpfSectionKind::License | EbpfSectionKind::Version => {}
        }

        Ok(())
    }

    /// Sanitize BPF functions.
    pub fn sanitize_functions(&mut self, features: &Features) {
        for function in self.functions.values_mut() {
            function.sanitize(features);
        }
    }
}

fn insn_is_helper_call(ins: &bpf_insn) -> bool {
    let klass = (ins.code & 0x07) as u32;
    let op = (ins.code & 0xF0) as u32;
    let src = (ins.code & 0x08) as u32;

    klass == BPF_JMP && op == BPF_CALL && src == BPF_K && ins.src_reg() == 0 && ins.dst_reg() == 0
}

const BPF_FUNC_PROBE_READ: i32 = 4;
const BPF_FUNC_PROBE_READ_STR: i32 = 45;
const BPF_FUNC_PROBE_READ_USER: i32 = 112;
const BPF_FUNC_PROBE_READ_KERNEL: i32 = 113;
const BPF_FUNC_PROBE_READ_USER_STR: i32 = 114;
const BPF_FUNC_PROBE_READ_KERNEL_STR: i32 = 115;

impl Function {
    fn sanitize(&mut self, features: &Features) {
        for inst in &mut self.instructions {
            if !insn_is_helper_call(inst) {
                continue;
            }

            match inst.imm {
                BPF_FUNC_PROBE_READ_USER | BPF_FUNC_PROBE_READ_KERNEL
                    if !features.bpf_probe_read_kernel =>
                {
                    inst.imm = BPF_FUNC_PROBE_READ;
                }
                BPF_FUNC_PROBE_READ_USER_STR | BPF_FUNC_PROBE_READ_KERNEL_STR
                    if !features.bpf_probe_read_kernel =>
                {
                    inst.imm = BPF_FUNC_PROBE_READ_STR;
                }
                _ => {}
            }
        }
    }
}

/// Errors caught during parsing the object file
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ParseError {
    #[error("error parsing ELF data")]
    ElfError(object::read::Error),

    /// Error parsing BTF object
    #[error("BTF error")]
    BtfError(#[from] BtfError),

    #[error("invalid license `{data:?}`: missing NULL terminator")]
    MissingLicenseNullTerminator { data: Vec<u8> },

    #[error("invalid license `{data:?}`")]
    InvalidLicense { data: Vec<u8> },

    #[error("invalid kernel version `{data:?}`")]
    InvalidKernelVersion { data: Vec<u8> },

    #[error("error parsing section with index {index}")]
    SectionError {
        index: usize,
        error: object::read::Error,
    },

    #[error("unsupported relocation target")]
    UnsupportedRelocationTarget,

    #[error("invalid program section `{section}`")]
    InvalidProgramSection { section: String },

    #[error("invalid program code")]
    InvalidProgramCode,

    #[error("error parsing map `{name}`")]
    InvalidMapDefinition { name: String },

    #[error("two or more symbols in section `{section_index}` have the same address {address:#X}")]
    SymbolTableConflict { section_index: usize, address: u64 },

    #[error("unknown symbol in section `{section_index}` at address {address:#X}")]
    UnknownSymbol { section_index: usize, address: u64 },

    #[error("invalid symbol, index `{index}` name: {}", .name.as_ref().unwrap_or(&"[unknown]".into()))]
    InvalidSymbol { index: usize, name: Option<String> },

    #[error("symbol {name} has size `{sym_size}`, but provided data is of size `{data_size}`")]
    InvalidGlobalData {
        name: String,
        sym_size: u64,
        data_size: usize,
    },

    #[error("symbol with name {name} not found in the symbols table")]
    SymbolNotFound { name: String },

    #[error("map for section with index {index} not found")]
    MapNotFound { index: usize },

    #[error("the map number {i} in the `maps` section doesn't have a symbol name")]
    MapSymbolNameNotFound { i: usize },

    #[error("no symbols found in the {section_name} section")]
    NoSymbolsForSection { section_name: String },

    /// No BTF parsed for object
    #[error("no BTF parsed for object")]
    NoBTF,
}

/// Invalid bindings to the bpf type from the parsed/received value.
pub struct InvalidTypeBinding<T> {
    /// The value parsed/received.
    pub value: T,
}

/// The kind of an ELF section.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EbpfSectionKind {
    /// Undefined
    Undefined,
    /// `maps`
    Maps,
    /// `.maps`
    BtfMaps,
    /// A program section
    Program,
    /// `.data`
    Data,
    /// `.rodata`
    Rodata,
    /// `.bss`
    Bss,
    /// `.text`
    Text,
    /// `.BTF`
    Btf,
    /// `.BTF.ext`
    BtfExt,
    /// `license`
    License,
    /// `version`
    Version,
}

impl EbpfSectionKind {
    fn from_name(name: &str) -> EbpfSectionKind {
        if name.starts_with("license") {
            EbpfSectionKind::License
        } else if name.starts_with("version") {
            EbpfSectionKind::Version
        } else if name.starts_with("maps") {
            EbpfSectionKind::Maps
        } else if name.starts_with(".maps") {
            EbpfSectionKind::BtfMaps
        } else if name.starts_with(".text") {
            EbpfSectionKind::Text
        } else if name.starts_with(".bss") {
            EbpfSectionKind::Bss
        } else if name.starts_with(".data") {
            EbpfSectionKind::Data
        } else if name.starts_with(".rodata") {
            EbpfSectionKind::Rodata
        } else if name == ".BTF" {
            EbpfSectionKind::Btf
        } else if name == ".BTF.ext" {
            EbpfSectionKind::BtfExt
        } else {
            EbpfSectionKind::Undefined
        }
    }
}

#[derive(Debug)]
struct Section<'a> {
    index: SectionIndex,
    kind: EbpfSectionKind,
    address: u64,
    name: &'a str,
    data: &'a [u8],
    size: u64,
    relocations: Vec<Relocation>,
}

impl<'a> TryFrom<&'a ObjSection<'_, '_>> for Section<'a> {
    type Error = ParseError;

    fn try_from(section: &'a ObjSection) -> Result<Section<'a>, ParseError> {
        let index = section.index();
        let map_err = |error| ParseError::SectionError {
            index: index.0,
            error,
        };
        let name = section.name().map_err(map_err)?;
        let kind = match EbpfSectionKind::from_name(name) {
            EbpfSectionKind::Undefined => {
                if section.kind() == SectionKind::Text && section.size() > 0 {
                    EbpfSectionKind::Program
                } else {
                    EbpfSectionKind::Undefined
                }
            }
            k => k,
        };
        Ok(Section {
            index,
            kind,
            address: section.address(),
            name,
            data: section.data().map_err(map_err)?,
            size: section.size(),
            relocations: section
                .relocations()
                .map(|(offset, r)| {
                    Ok(Relocation {
                        symbol_index: match r.target() {
                            RelocationTarget::Symbol(index) => index.0,
                            _ => return Err(ParseError::UnsupportedRelocationTarget),
                        },
                        offset,
                        size: r.size(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

fn parse_license(data: &[u8]) -> Result<CString, ParseError> {
    if data.len() < 2 {
        return Err(ParseError::InvalidLicense {
            data: data.to_vec(),
        });
    }
    if data[data.len() - 1] != 0 {
        return Err(ParseError::MissingLicenseNullTerminator {
            data: data.to_vec(),
        });
    }

    Ok(CStr::from_bytes_with_nul(data)
        .map_err(|_| ParseError::InvalidLicense {
            data: data.to_vec(),
        })?
        .to_owned())
}

fn parse_version(data: &[u8], endianness: object::Endianness) -> Result<Option<u32>, ParseError> {
    let data = match data.len() {
        4 => data.try_into().unwrap(),
        _ => {
            return Err(ParseError::InvalidKernelVersion {
                data: data.to_vec(),
            })
        }
    };

    let v = match endianness {
        object::Endianness::Big => u32::from_be_bytes(data),
        object::Endianness::Little => u32::from_le_bytes(data),
    };

    Ok(if v == KERNEL_VERSION_ANY {
        None
    } else {
        Some(v)
    })
}

// Gets an integer value from a BTF map defintion K/V pair.
// type_id should be a PTR to an ARRAY.
// the value is encoded in the array nr_elems field.
fn get_map_field(btf: &Btf, type_id: u32) -> Result<u32, BtfError> {
    let pty = match &btf.type_by_id(type_id)? {
        BtfType::Ptr(pty) => pty,
        other => {
            return Err(BtfError::UnexpectedBtfType {
                type_id: other.btf_type().unwrap_or(0),
            })
        }
    };
    // Safety: union
    let arr = match &btf.type_by_id(pty.btf_type)? {
        BtfType::Array(Array { array, .. }) => array,
        other => {
            return Err(BtfError::UnexpectedBtfType {
                type_id: other.btf_type().unwrap_or(0),
            })
        }
    };
    Ok(arr.len)
}

// Parsed '.bss' '.data' and '.rodata' sections. These sections are arrays of
// bytes and are relocated based on their section index.
fn parse_data_map_section(section: &Section) -> Result<Map, ParseError> {
    let (def, data) = match section.kind {
        EbpfSectionKind::Bss | EbpfSectionKind::Data | EbpfSectionKind::Rodata => {
            let def = bpf_map_def {
                map_type: BPF_MAP_TYPE_ARRAY as u32,
                key_size: mem::size_of::<u32>() as u32,
                // We need to use section.size here since
                // .bss will always have data.len() == 0
                value_size: section.size as u32,
                max_entries: 1,
                map_flags: if section.kind == EbpfSectionKind::Rodata {
                    BPF_F_RDONLY_PROG
                } else {
                    0
                },
                ..Default::default()
            };
            (def, section.data.to_vec())
        }
        _ => unreachable!(),
    };
    Ok(Map::Legacy(LegacyMap {
        section_index: section.index.0,
        section_kind: section.kind,
        // Data maps don't require symbols to be relocated
        symbol_index: None,
        def,
        data,
    }))
}

fn parse_map_def(name: &str, data: &[u8]) -> Result<bpf_map_def, ParseError> {
    if data.len() < MINIMUM_MAP_SIZE {
        return Err(ParseError::InvalidMapDefinition {
            name: name.to_owned(),
        });
    }

    if data.len() < mem::size_of::<bpf_map_def>() {
        let mut map_def = bpf_map_def::default();
        unsafe {
            let map_def_ptr =
                from_raw_parts_mut(&mut map_def as *mut bpf_map_def as *mut u8, data.len());
            map_def_ptr.copy_from_slice(data);
        }
        Ok(map_def)
    } else {
        Ok(unsafe { ptr::read_unaligned(data.as_ptr() as *const bpf_map_def) })
    }
}

fn parse_btf_map_def(btf: &Btf, info: &DataSecEntry) -> Result<(String, BtfMapDef), BtfError> {
    let ty = match btf.type_by_id(info.btf_type)? {
        BtfType::Var(var) => var,
        other => {
            return Err(BtfError::UnexpectedBtfType {
                type_id: other.btf_type().unwrap_or(0),
            })
        }
    };
    let map_name = btf.string_at(ty.name_offset)?;
    let mut map_def = BtfMapDef::default();

    // Safety: union
    let root_type = btf.resolve_type(ty.btf_type)?;
    let s = match btf.type_by_id(root_type)? {
        BtfType::Struct(s) => s,
        other => {
            return Err(BtfError::UnexpectedBtfType {
                type_id: other.btf_type().unwrap_or(0),
            })
        }
    };

    for m in &s.members {
        match btf.string_at(m.name_offset)?.as_ref() {
            "type" => {
                map_def.map_type = get_map_field(btf, m.btf_type)?;
            }
            "key" => {
                if let BtfType::Ptr(pty) = btf.type_by_id(m.btf_type)? {
                    // Safety: union
                    let t = pty.btf_type;
                    map_def.key_size = btf.type_size(t)? as u32;
                    map_def.btf_key_type_id = t;
                } else {
                    return Err(BtfError::UnexpectedBtfType {
                        type_id: m.btf_type,
                    });
                }
            }
            "key_size" => {
                map_def.key_size = get_map_field(btf, m.btf_type)?;
            }
            "value" => {
                if let BtfType::Ptr(pty) = btf.type_by_id(m.btf_type)? {
                    let t = pty.btf_type;
                    map_def.value_size = btf.type_size(t)? as u32;
                    map_def.btf_value_type_id = t;
                } else {
                    return Err(BtfError::UnexpectedBtfType {
                        type_id: m.btf_type,
                    });
                }
            }
            "value_size" => {
                map_def.value_size = get_map_field(btf, m.btf_type)?;
            }
            "max_entries" => {
                map_def.max_entries = get_map_field(btf, m.btf_type)?;
            }
            "map_flags" => {
                map_def.map_flags = get_map_field(btf, m.btf_type)?;
            }
            "pinning" => {
                let pinning = get_map_field(btf, m.btf_type)?;
                map_def.pinning = PinningType::try_from(pinning).unwrap_or_else(|_| {
                    debug!("{} is not a valid pin type. using PIN_NONE", pinning);
                    PinningType::None
                });
            }
            other => {
                debug!("skipping unknown map section: {}", other);
                continue;
            }
        }
    }
    Ok((map_name.to_string(), map_def))
}

/// Parses a [bpf_map_info] into a [Map].
pub fn parse_map_info(info: bpf_map_info, pinned: PinningType) -> Map {
    if info.btf_key_type_id != 0 {
        Map::Btf(BtfMap {
            def: BtfMapDef {
                map_type: info.type_,
                key_size: info.key_size,
                value_size: info.value_size,
                max_entries: info.max_entries,
                map_flags: info.map_flags,
                pinning: pinned,
                btf_key_type_id: info.btf_key_type_id,
                btf_value_type_id: info.btf_value_type_id,
            },
            section_index: 0,
            symbol_index: 0,
            data: Vec::new(),
        })
    } else {
        Map::Legacy(LegacyMap {
            def: bpf_map_def {
                map_type: info.type_,
                key_size: info.key_size,
                value_size: info.value_size,
                max_entries: info.max_entries,
                map_flags: info.map_flags,
                pinning: pinned,
                id: info.id,
            },
            section_index: 0,
            symbol_index: None,
            section_kind: EbpfSectionKind::Undefined,
            data: Vec::new(),
        })
    }
}

/// Copies a block of eBPF instructions
pub fn copy_instructions(data: &[u8]) -> Result<Vec<bpf_insn>, ParseError> {
    if data.len() % mem::size_of::<bpf_insn>() > 0 {
        return Err(ParseError::InvalidProgramCode);
    }
    let instructions = data
        .chunks_exact(mem::size_of::<bpf_insn>())
        .map(|d| unsafe { ptr::read_unaligned(d.as_ptr() as *const bpf_insn) })
        .collect::<Vec<_>>();
    Ok(instructions)
}

fn get_func_and_line_info(
    btf_ext: Option<&BtfExt>,
    symbol: &Symbol,
    section: &Section,
    offset: usize,
    rewrite_insn_off: bool,
) -> (FuncSecInfo, LineSecInfo, usize, usize) {
    btf_ext
        .map(|btf_ext| {
            let instruction_offset = (offset / INS_SIZE) as u32;
            let symbol_size_instructions = (symbol.size as usize / INS_SIZE) as u32;

            let mut func_info = btf_ext.func_info.get(section.name);
            func_info.func_info.retain_mut(|f| {
                let retain = f.insn_off == instruction_offset;
                if retain && rewrite_insn_off {
                    f.insn_off = 0;
                }
                retain
            });

            let mut line_info = btf_ext.line_info.get(section.name);
            line_info
                .line_info
                .retain_mut(|l| match l.insn_off.checked_sub(instruction_offset) {
                    None => false,
                    Some(insn_off) => {
                        let retain = insn_off < symbol_size_instructions;
                        if retain && rewrite_insn_off {
                            l.insn_off = insn_off
                        }
                        retain
                    }
                });
            (
                func_info,
                line_info,
                btf_ext.func_info_rec_size(),
                btf_ext.line_info_rec_size(),
            )
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use assert_matches::assert_matches;

    use super::*;
    use crate::generated::btf_ext_header;

    const FAKE_INS_LEN: u64 = 8;

    fn fake_section<'a>(
        kind: EbpfSectionKind,
        name: &'a str,
        data: &'a [u8],
        index: Option<usize>,
    ) -> Section<'a> {
        let idx = index.unwrap_or(0);
        Section {
            index: SectionIndex(idx),
            kind,
            address: 0,
            name,
            data,
            size: data.len() as u64,
            relocations: Vec::new(),
        }
    }

    fn fake_ins() -> bpf_insn {
        bpf_insn {
            code: 0,
            _bitfield_align_1: [],
            _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
            off: 0,
            imm: 0,
        }
    }

    fn fake_sym(obj: &mut Object, section_index: usize, address: u64, name: &str, size: u64) {
        let idx = obj.symbol_table.len();
        obj.symbol_table.insert(
            idx + 1,
            Symbol {
                index: idx + 1,
                section_index: Some(section_index),
                name: Some(name.to_string()),
                address,
                size,
                is_definition: false,
                kind: SymbolKind::Text,
            },
        );
        obj.symbols_by_section
            .entry(SectionIndex(section_index))
            .or_default()
            .push(idx + 1);
    }

    fn bytes_of<T>(val: &T) -> &[u8] {
        // Safety: This is for testing only
        unsafe { crate::util::bytes_of(val) }
    }

    #[test]
    fn test_parse_generic_error() {
        assert_matches!(Object::parse(&b"foo"[..]), Err(ParseError::ElfError(_)))
    }

    #[test]
    fn test_parse_license() {
        assert_matches!(parse_license(b""), Err(ParseError::InvalidLicense { .. }));

        assert_matches!(parse_license(b"\0"), Err(ParseError::InvalidLicense { .. }));

        assert_matches!(
            parse_license(b"GPL"),
            Err(ParseError::MissingLicenseNullTerminator { .. })
        );

        assert_eq!(parse_license(b"GPL\0").unwrap().to_str().unwrap(), "GPL");
    }

    #[test]
    fn test_parse_version() {
        assert_matches!(
            parse_version(b"", Endianness::Little),
            Err(ParseError::InvalidKernelVersion { .. })
        );

        assert_matches!(
            parse_version(b"123", Endianness::Little),
            Err(ParseError::InvalidKernelVersion { .. })
        );

        assert_matches!(
            parse_version(&0xFFFF_FFFEu32.to_le_bytes(), Endianness::Little),
            Ok(None)
        );

        assert_matches!(
            parse_version(&0xFFFF_FFFEu32.to_be_bytes(), Endianness::Big),
            Ok(None)
        );

        assert_matches!(
            parse_version(&1234u32.to_le_bytes(), Endianness::Little),
            Ok(Some(1234))
        );
    }

    #[test]
    fn test_parse_map_def_error() {
        assert_matches!(
            parse_map_def("foo", &[]),
            Err(ParseError::InvalidMapDefinition { .. })
        );
    }

    #[test]
    fn test_parse_map_short() {
        let def = bpf_map_def {
            map_type: 1,
            key_size: 2,
            value_size: 3,
            max_entries: 4,
            map_flags: 5,
            id: 0,
            pinning: PinningType::None,
        };

        assert_eq!(
            parse_map_def("foo", &bytes_of(&def)[..MINIMUM_MAP_SIZE]).unwrap(),
            def
        );
    }

    #[test]
    fn test_parse_map_def() {
        let def = bpf_map_def {
            map_type: 1,
            key_size: 2,
            value_size: 3,
            max_entries: 4,
            map_flags: 5,
            id: 6,
            pinning: PinningType::ByName,
        };

        assert_eq!(parse_map_def("foo", bytes_of(&def)).unwrap(), def);
    }

    #[test]
    fn test_parse_map_def_with_padding() {
        let def = bpf_map_def {
            map_type: 1,
            key_size: 2,
            value_size: 3,
            max_entries: 4,
            map_flags: 5,
            id: 6,
            pinning: PinningType::ByName,
        };
        let mut buf = [0u8; 128];
        unsafe { ptr::write_unaligned(buf.as_mut_ptr() as *mut _, def) };

        assert_eq!(parse_map_def("foo", &buf).unwrap(), def);
    }

    #[test]
    fn test_parse_map_data() {
        let map_data = b"map data";
        assert_matches!(
            parse_data_map_section(
                &fake_section(
                    EbpfSectionKind::Data,
                    ".bss",
                    map_data,
                    None,
                ),
            ),
            Ok(Map::Legacy(LegacyMap {
                section_index: 0,
                section_kind: EbpfSectionKind::Data,
                symbol_index: None,
                def: bpf_map_def {
                    map_type: _map_type,
                    key_size: 4,
                    value_size,
                    max_entries: 1,
                    map_flags: 0,
                    id: 0,
                    pinning: PinningType::None,
                },
                data,
            })) if data == map_data && value_size == map_data.len() as u32
        )
    }

    fn fake_obj() -> Object {
        Object::new(Endianness::Little, CString::new("GPL").unwrap(), None)
    }

    #[test]
    fn sanitizes_empty_btf_files_to_none() {
        let mut obj = fake_obj();

        let btf = Btf::new();
        let btf_bytes = btf.to_bytes();
        obj.parse_section(fake_section(EbpfSectionKind::Btf, ".BTF", &btf_bytes, None))
            .unwrap();

        const FUNC_INFO_LEN: u32 = 4;
        const LINE_INFO_LEN: u32 = 4;
        const CORE_RELO_LEN: u32 = 16;
        let ext_header = btf_ext_header {
            magic: 0xeb9f,
            version: 1,
            flags: 0,
            hdr_len: 24,
            func_info_off: 0,
            func_info_len: FUNC_INFO_LEN,
            line_info_off: FUNC_INFO_LEN,
            line_info_len: LINE_INFO_LEN,
            core_relo_off: FUNC_INFO_LEN + LINE_INFO_LEN,
            core_relo_len: CORE_RELO_LEN,
        };
        let btf_ext_bytes = bytes_of::<btf_ext_header>(&ext_header).to_vec();
        obj.parse_section(fake_section(
            EbpfSectionKind::BtfExt,
            ".BTF.ext",
            &btf_ext_bytes,
            None,
        ))
        .unwrap();

        let btf = obj.fixup_and_sanitize_btf(&BtfFeatures::default()).unwrap();
        assert!(btf.is_none());
    }

    #[test]
    fn test_parse_program_error() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", 1);
        assert_matches!(
            obj.parse_programs(&fake_section(
                EbpfSectionKind::Program,
                "kprobe/foo",
                &42u32.to_ne_bytes(),
                None,
            ),),
            Err(ParseError::InvalidProgramCode)
        );
    }

    #[test]
    fn test_parse_program() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        obj.parse_programs(&fake_section(
            EbpfSectionKind::Program,
            "kprobe/foo",
            bytes_of(&fake_ins()),
            None,
        ))
        .unwrap();

        let prog_foo = obj.programs.get("foo").unwrap();

        assert_matches!(prog_foo, Program {
            license,
            kernel_version: None,
            section: ProgramSection::KProbe { .. },
            ..
        } => assert_eq!(license.to_str().unwrap(), "GPL"));

        assert_matches!(
            obj.functions.get(&prog_foo.function_key()),
            Some(Function {
                name,
                address: 0,
                section_index: SectionIndex(0),
                section_offset: 0,
                instructions,
            ..}) if name == "foo" && instructions.len() == 1
        )
    }

    #[test]
    fn test_parse_section_map() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", mem::size_of::<bpf_map_def>() as u64);
        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Maps,
                "maps/foo",
                bytes_of(&bpf_map_def {
                    map_type: 1,
                    key_size: 2,
                    value_size: 3,
                    max_entries: 4,
                    map_flags: 5,
                    ..Default::default()
                }),
                None,
            )),
            Ok(())
        );
        assert!(obj.maps.contains_key("foo"));
    }

    #[test]
    fn test_parse_multiple_program_in_same_section() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);
        fake_sym(&mut obj, 0, FAKE_INS_LEN, "bar", FAKE_INS_LEN);

        let insns = [fake_ins(), fake_ins()];
        let data = bytes_of(&insns);

        obj.parse_programs(&fake_section(
            EbpfSectionKind::Program,
            "kprobe",
            data,
            None,
        ))
        .unwrap();

        let prog_foo = obj.programs.get("foo").unwrap();
        let function_foo = obj.functions.get(&prog_foo.function_key()).unwrap();
        let prog_bar = obj.programs.get("bar").unwrap();
        let function_bar = obj.functions.get(&prog_bar.function_key()).unwrap();

        assert_matches!(prog_foo, Program {
            license,
            kernel_version: None,
            section: ProgramSection::KProbe { .. },
            ..
        } => assert_eq!(license.to_str().unwrap(), "GPL"));
        assert_matches!(
            function_foo,
            Function {
                name,
                address: 0,
                section_index: SectionIndex(0),
                section_offset: 0,
                instructions,
                ..
            }  if name == "foo" && instructions.len() == 1
        );

        assert_matches!(prog_bar, Program {
            license,
            kernel_version: None,
            section: ProgramSection::KProbe { .. },
            ..
        } => assert_eq!(license.to_str().unwrap(), "GPL"));
        assert_matches!(
            function_bar,
            Function {
                name,
                address: 8,
                section_index: SectionIndex(0),
                section_offset: 8,
                instructions,
                ..
            }  if name == "bar" && instructions.len() == 1
        );
    }

    #[test]
    fn test_parse_section_multiple_maps() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", mem::size_of::<bpf_map_def>() as u64);
        fake_sym(&mut obj, 0, 28, "bar", mem::size_of::<bpf_map_def>() as u64);
        fake_sym(&mut obj, 0, 60, "baz", mem::size_of::<bpf_map_def>() as u64);
        let def = &bpf_map_def {
            map_type: 1,
            key_size: 2,
            value_size: 3,
            max_entries: 4,
            map_flags: 5,
            ..Default::default()
        };
        let map_data = bytes_of(def).to_vec();
        let mut buf = vec![];
        buf.extend(&map_data);
        buf.extend(&map_data);
        // throw in some padding
        buf.extend([0, 0, 0, 0]);
        buf.extend(&map_data);
        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Maps,
                "maps",
                buf.as_slice(),
                None
            )),
            Ok(())
        );
        assert!(obj.maps.contains_key("foo"));
        assert!(obj.maps.contains_key("bar"));
        assert!(obj.maps.contains_key("baz"));
        for map in obj.maps.values() {
            assert_matches!(map, Map::Legacy(m) => {
                assert_eq!(&m.def, def);
            })
        }
    }

    #[test]
    fn test_parse_section_data() {
        let mut obj = fake_obj();
        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Data,
                ".bss",
                b"map data",
                None
            )),
            Ok(())
        );
        assert!(obj.maps.contains_key(".bss"));

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Data,
                ".rodata",
                b"map data",
                None
            )),
            Ok(())
        );
        assert!(obj.maps.contains_key(".rodata"));

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Data,
                ".rodata.boo",
                b"map data",
                None
            )),
            Ok(())
        );
        assert!(obj.maps.contains_key(".rodata.boo"));

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Data,
                ".data",
                b"map data",
                None
            )),
            Ok(())
        );
        assert!(obj.maps.contains_key(".data"));

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Data,
                ".data.boo",
                b"map data",
                None
            )),
            Ok(())
        );
        assert!(obj.maps.contains_key(".data.boo"));
    }

    #[test]
    fn test_parse_section_kprobe() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "kprobe/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::KProbe { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_uprobe() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "uprobe/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::UProbe { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_uprobe_sleepable() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "uprobe.s/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::UProbe {
                    sleepable: true,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_uretprobe() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "uretprobe/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::URetProbe { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_uretprobe_sleepable() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "uretprobe.s/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::URetProbe {
                    sleepable: true,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_trace_point() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);
        fake_sym(&mut obj, 1, 0, "bar", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "tracepoint/cat/name",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::TracePoint { .. },
                ..
            })
        );

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "tp/foo/bar",
                bytes_of(&fake_ins()),
                Some(1),
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("bar"),
            Some(Program {
                section: ProgramSection::TracePoint { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_socket_filter() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "socket/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::SocketFilter { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_xdp() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "xdp",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::Xdp { frags: false, .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_xdp_frags() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "xdp.frags",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::Xdp { frags: true, .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_raw_tp() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);
        fake_sym(&mut obj, 1, 0, "bar", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "raw_tp/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::RawTracePoint { .. },
                ..
            })
        );

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "raw_tracepoint/bar",
                bytes_of(&fake_ins()),
                Some(1)
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("bar"),
            Some(Program {
                section: ProgramSection::RawTracePoint { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_lsm() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "lsm/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::Lsm {
                    sleepable: false,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_lsm_sleepable() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "lsm.s/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::Lsm {
                    sleepable: true,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_btf_tracepoint() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "tp_btf/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::BtfTracePoint { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_skskb_unnamed() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "stream_parser", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "sk_skb/stream_parser",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("stream_parser"),
            Some(Program {
                section: ProgramSection::SkSkbStreamParser { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_skskb_named() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "my_parser", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "sk_skb/stream_parser/my_parser",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("my_parser"),
            Some(Program {
                section: ProgramSection::SkSkbStreamParser { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_fentry() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "fentry/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::FEntry { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_fentry_sleepable() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "fentry.s/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::FEntry {
                    sleepable: true,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_fexit() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "fexit/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::FExit { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_fexit_sleepable() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "fexit.s/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::FExit {
                    sleepable: true,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_cgroup_skb_ingress_unnamed() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "ingress", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup_skb/ingress",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("ingress"),
            Some(Program {
                section: ProgramSection::CgroupSkbIngress { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_cgroup_skb_ingress_named() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup_skb/ingress/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::CgroupSkbIngress { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_cgroup_skb_no_direction_unamed() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "skb", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup/skb",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("skb"),
            Some(Program {
                section: ProgramSection::CgroupSkb { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_cgroup_skb_no_direction_named() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup/skb/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::CgroupSkb { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_sock_addr_named() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup/connect4/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::CgroupSockAddr {
                    attach_type: CgroupSockAddrAttachType::Connect4,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_sock_addr_unnamed() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "connect4", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup/connect4",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("connect4"),
            Some(Program {
                section: ProgramSection::CgroupSockAddr {
                    attach_type: CgroupSockAddrAttachType::Connect4,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_sockopt_named() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup/getsockopt/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::CgroupSockopt {
                    attach_type: CgroupSockoptAttachType::Get,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_sockopt_unnamed() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "getsockopt", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup/getsockopt",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("getsockopt"),
            Some(Program {
                section: ProgramSection::CgroupSockopt {
                    attach_type: CgroupSockoptAttachType::Get,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_patch_map_data() {
        let mut obj = fake_obj();
        obj.maps.insert(
            ".rodata".to_owned(),
            Map::Legacy(LegacyMap {
                def: bpf_map_def {
                    map_type: BPF_MAP_TYPE_ARRAY as u32,
                    key_size: mem::size_of::<u32>() as u32,
                    value_size: 3,
                    max_entries: 1,
                    map_flags: BPF_F_RDONLY_PROG,
                    id: 1,
                    pinning: PinningType::None,
                },
                section_index: 1,
                section_kind: EbpfSectionKind::Rodata,
                symbol_index: Some(1),
                data: vec![0, 0, 0],
            }),
        );
        obj.symbol_table.insert(
            1,
            Symbol {
                index: 1,
                section_index: Some(1),
                name: Some("my_config".to_owned()),
                address: 0,
                size: 3,
                is_definition: true,
                kind: SymbolKind::Data,
            },
        );

        let test_data: &[u8] = &[1, 2, 3];
        obj.patch_map_data(HashMap::from([
            ("my_config", (test_data, true)),
            ("optional_variable", (test_data, false)),
        ]))
        .unwrap();

        let map = obj.maps.get(".rodata").unwrap();
        assert_eq!(test_data, map.data());
    }

    #[test]
    fn test_parse_btf_map_section() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "map_1", 0);
        fake_sym(&mut obj, 0, 0, "map_2", 0);
        // generated from:
        // objcopy --dump-section .BTF=test.btf ./target/bpfel-unknown-none/debug/multimap-btf.bpf.o
        // hexdump -v  -e '7/1 "0x%02X, " 1/1  " 0x%02X,\n"' test.btf
        #[cfg(target_endian = "little")]
        let data: &[u8] = &[
            0x9F, 0xEB, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x01,
            0x00, 0x00, 0xF0, 0x01, 0x00, 0x00, 0xCC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x06, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
            0x07, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
            0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0x09, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x0A, 0x00,
            0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00,
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0C, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x04, 0x20, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x05, 0x00,
            0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x80, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xC0, 0x00,
            0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x0D, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x04, 0x20, 0x00,
            0x00, 0x00, 0x45, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x4A, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x4E, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00,
            0x0B, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x0E, 0x0F, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
            0x70, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0C, 0x12, 0x00, 0x00, 0x00, 0xB0, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xB5, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x0E, 0x15, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xBE, 0x01,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0xC4, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0F,
            0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x69, 0x6E, 0x74, 0x00, 0x5F, 0x5F, 0x41, 0x52, 0x52, 0x41, 0x59,
            0x5F, 0x53, 0x49, 0x5A, 0x45, 0x5F, 0x54, 0x59, 0x50, 0x45, 0x5F, 0x5F, 0x00, 0x5F,
            0x5F, 0x75, 0x33, 0x32, 0x00, 0x75, 0x6E, 0x73, 0x69, 0x67, 0x6E, 0x65, 0x64, 0x20,
            0x69, 0x6E, 0x74, 0x00, 0x5F, 0x5F, 0x75, 0x36, 0x34, 0x00, 0x75, 0x6E, 0x73, 0x69,
            0x67, 0x6E, 0x65, 0x64, 0x20, 0x6C, 0x6F, 0x6E, 0x67, 0x20, 0x6C, 0x6F, 0x6E, 0x67,
            0x00, 0x74, 0x79, 0x70, 0x65, 0x00, 0x6B, 0x65, 0x79, 0x00, 0x76, 0x61, 0x6C, 0x75,
            0x65, 0x00, 0x6D, 0x61, 0x78, 0x5F, 0x65, 0x6E, 0x74, 0x72, 0x69, 0x65, 0x73, 0x00,
            0x6D, 0x61, 0x70, 0x5F, 0x31, 0x00, 0x6D, 0x61, 0x70, 0x5F, 0x32, 0x00, 0x63, 0x74,
            0x78, 0x00, 0x62, 0x70, 0x66, 0x5F, 0x70, 0x72, 0x6F, 0x67, 0x00, 0x74, 0x72, 0x61,
            0x63, 0x65, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x00, 0x2F, 0x76, 0x61, 0x72, 0x2F, 0x68,
            0x6F, 0x6D, 0x65, 0x2F, 0x64, 0x61, 0x76, 0x65, 0x2F, 0x64, 0x65, 0x76, 0x2F, 0x61,
            0x79, 0x61, 0x2D, 0x72, 0x73, 0x2F, 0x61, 0x79, 0x61, 0x2F, 0x74, 0x65, 0x73, 0x74,
            0x2F, 0x69, 0x6E, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2D, 0x65,
            0x62, 0x70, 0x66, 0x2F, 0x73, 0x72, 0x63, 0x2F, 0x62, 0x70, 0x66, 0x2F, 0x6D, 0x75,
            0x6C, 0x74, 0x69, 0x6D, 0x61, 0x70, 0x2D, 0x62, 0x74, 0x66, 0x2E, 0x62, 0x70, 0x66,
            0x2E, 0x63, 0x00, 0x69, 0x6E, 0x74, 0x20, 0x62, 0x70, 0x66, 0x5F, 0x70, 0x72, 0x6F,
            0x67, 0x28, 0x76, 0x6F, 0x69, 0x64, 0x20, 0x2A, 0x63, 0x74, 0x78, 0x29, 0x00, 0x09,
            0x5F, 0x5F, 0x75, 0x33, 0x32, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x3D, 0x20, 0x30, 0x3B,
            0x00, 0x09, 0x5F, 0x5F, 0x75, 0x36, 0x34, 0x20, 0x74, 0x77, 0x65, 0x6E, 0x74, 0x79,
            0x5F, 0x66, 0x6F, 0x75, 0x72, 0x20, 0x3D, 0x20, 0x32, 0x34, 0x3B, 0x00, 0x09, 0x5F,
            0x5F, 0x75, 0x36, 0x34, 0x20, 0x66, 0x6F, 0x72, 0x74, 0x79, 0x5F, 0x74, 0x77, 0x6F,
            0x20, 0x3D, 0x20, 0x34, 0x32, 0x3B, 0x00, 0x20, 0x20, 0x20, 0x20, 0x62, 0x70, 0x66,
            0x5F, 0x6D, 0x61, 0x70, 0x5F, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5F, 0x65, 0x6C,
            0x65, 0x6D, 0x28, 0x26, 0x6D, 0x61, 0x70, 0x5F, 0x31, 0x2C, 0x20, 0x26, 0x6B, 0x65,
            0x79, 0x2C, 0x20, 0x26, 0x74, 0x77, 0x65, 0x6E, 0x74, 0x79, 0x5F, 0x66, 0x6F, 0x75,
            0x72, 0x2C, 0x20, 0x42, 0x50, 0x46, 0x5F, 0x41, 0x4E, 0x59, 0x29, 0x3B, 0x00, 0x20,
            0x20, 0x20, 0x20, 0x62, 0x70, 0x66, 0x5F, 0x6D, 0x61, 0x70, 0x5F, 0x75, 0x70, 0x64,
            0x61, 0x74, 0x65, 0x5F, 0x65, 0x6C, 0x65, 0x6D, 0x28, 0x26, 0x6D, 0x61, 0x70, 0x5F,
            0x32, 0x2C, 0x20, 0x26, 0x6B, 0x65, 0x79, 0x2C, 0x20, 0x26, 0x66, 0x6F, 0x72, 0x74,
            0x79, 0x5F, 0x74, 0x77, 0x6F, 0x2C, 0x20, 0x42, 0x50, 0x46, 0x5F, 0x41, 0x4E, 0x59,
            0x29, 0x3B, 0x00, 0x09, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6E, 0x20, 0x30, 0x3B, 0x00,
            0x63, 0x68, 0x61, 0x72, 0x00, 0x5F, 0x6C, 0x69, 0x63, 0x65, 0x6E, 0x73, 0x65, 0x00,
            0x2E, 0x6D, 0x61, 0x70, 0x73, 0x00, 0x6C, 0x69, 0x63, 0x65, 0x6E, 0x73, 0x65, 0x00,
        ];
        #[cfg(target_endian = "big")]
        let data: &[u8] = &[
            0xEB, 0x9F, 0x01, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0xF0, 0x00, 0x00, 0x01, 0xF0, 0x00, 0x00, 0x01, 0xCC, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x19, 0x08, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x1F, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x2C, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x0A, 0x00, 0x00, 0x00, 0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x45,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00,
            0x00, 0x05, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00,
            0x00, 0xC0, 0x00, 0x00, 0x00, 0x60, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x04, 0x00, 0x00,
            0x00, 0x20, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x4E, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x54,
            0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x66, 0x0E, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x11,
            0x00, 0x00, 0x00, 0x70, 0x0C, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00,
            0x01, 0xB0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x14, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0xB5,
            0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x01, 0xBE, 0x0F, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x01, 0xC4, 0x0F, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x69, 0x6E, 0x74, 0x00, 0x5F, 0x5F, 0x41, 0x52, 0x52, 0x41, 0x59,
            0x5F, 0x53, 0x49, 0x5A, 0x45, 0x5F, 0x54, 0x59, 0x50, 0x45, 0x5F, 0x5F, 0x00, 0x5F,
            0x5F, 0x75, 0x33, 0x32, 0x00, 0x75, 0x6E, 0x73, 0x69, 0x67, 0x6E, 0x65, 0x64, 0x20,
            0x69, 0x6E, 0x74, 0x00, 0x5F, 0x5F, 0x75, 0x36, 0x34, 0x00, 0x75, 0x6E, 0x73, 0x69,
            0x67, 0x6E, 0x65, 0x64, 0x20, 0x6C, 0x6F, 0x6E, 0x67, 0x20, 0x6C, 0x6F, 0x6E, 0x67,
            0x00, 0x74, 0x79, 0x70, 0x65, 0x00, 0x6B, 0x65, 0x79, 0x00, 0x76, 0x61, 0x6C, 0x75,
            0x65, 0x00, 0x6D, 0x61, 0x78, 0x5F, 0x65, 0x6E, 0x74, 0x72, 0x69, 0x65, 0x73, 0x00,
            0x6D, 0x61, 0x70, 0x5F, 0x31, 0x00, 0x6D, 0x61, 0x70, 0x5F, 0x32, 0x00, 0x63, 0x74,
            0x78, 0x00, 0x62, 0x70, 0x66, 0x5F, 0x70, 0x72, 0x6F, 0x67, 0x00, 0x74, 0x72, 0x61,
            0x63, 0x65, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x00, 0x2F, 0x76, 0x61, 0x72, 0x2F, 0x68,
            0x6F, 0x6D, 0x65, 0x2F, 0x64, 0x61, 0x76, 0x65, 0x2F, 0x64, 0x65, 0x76, 0x2F, 0x61,
            0x79, 0x61, 0x2D, 0x72, 0x73, 0x2F, 0x61, 0x79, 0x61, 0x2F, 0x74, 0x65, 0x73, 0x74,
            0x2F, 0x69, 0x6E, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2D, 0x65,
            0x62, 0x70, 0x66, 0x2F, 0x73, 0x72, 0x63, 0x2F, 0x62, 0x70, 0x66, 0x2F, 0x6D, 0x75,
            0x6C, 0x74, 0x69, 0x6D, 0x61, 0x70, 0x2D, 0x62, 0x74, 0x66, 0x2E, 0x62, 0x70, 0x66,
            0x2E, 0x63, 0x00, 0x69, 0x6E, 0x74, 0x20, 0x62, 0x70, 0x66, 0x5F, 0x70, 0x72, 0x6F,
            0x67, 0x28, 0x76, 0x6F, 0x69, 0x64, 0x20, 0x2A, 0x63, 0x74, 0x78, 0x29, 0x00, 0x09,
            0x5F, 0x5F, 0x75, 0x33, 0x32, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x3D, 0x20, 0x30, 0x3B,
            0x00, 0x09, 0x5F, 0x5F, 0x75, 0x36, 0x34, 0x20, 0x74, 0x77, 0x65, 0x6E, 0x74, 0x79,
            0x5F, 0x66, 0x6F, 0x75, 0x72, 0x20, 0x3D, 0x20, 0x32, 0x34, 0x3B, 0x00, 0x09, 0x5F,
            0x5F, 0x75, 0x36, 0x34, 0x20, 0x66, 0x6F, 0x72, 0x74, 0x79, 0x5F, 0x74, 0x77, 0x6F,
            0x20, 0x3D, 0x20, 0x34, 0x32, 0x3B, 0x00, 0x20, 0x20, 0x20, 0x20, 0x62, 0x70, 0x66,
            0x5F, 0x6D, 0x61, 0x70, 0x5F, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5F, 0x65, 0x6C,
            0x65, 0x6D, 0x28, 0x26, 0x6D, 0x61, 0x70, 0x5F, 0x31, 0x2C, 0x20, 0x26, 0x6B, 0x65,
            0x79, 0x2C, 0x20, 0x26, 0x74, 0x77, 0x65, 0x6E, 0x74, 0x79, 0x5F, 0x66, 0x6F, 0x75,
            0x72, 0x2C, 0x20, 0x42, 0x50, 0x46, 0x5F, 0x41, 0x4E, 0x59, 0x29, 0x3B, 0x00, 0x20,
            0x20, 0x20, 0x20, 0x62, 0x70, 0x66, 0x5F, 0x6D, 0x61, 0x70, 0x5F, 0x75, 0x70, 0x64,
            0x61, 0x74, 0x65, 0x5F, 0x65, 0x6C, 0x65, 0x6D, 0x28, 0x26, 0x6D, 0x61, 0x70, 0x5F,
            0x32, 0x2C, 0x20, 0x26, 0x6B, 0x65, 0x79, 0x2C, 0x20, 0x26, 0x66, 0x6F, 0x72, 0x74,
            0x79, 0x5F, 0x74, 0x77, 0x6F, 0x2C, 0x20, 0x42, 0x50, 0x46, 0x5F, 0x41, 0x4E, 0x59,
            0x29, 0x3B, 0x00, 0x09, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6E, 0x20, 0x30, 0x3B, 0x00,
            0x63, 0x68, 0x61, 0x72, 0x00, 0x5F, 0x6C, 0x69, 0x63, 0x65, 0x6E, 0x73, 0x65, 0x00,
            0x2E, 0x6D, 0x61, 0x70, 0x73, 0x00, 0x6C, 0x69, 0x63, 0x65, 0x6E, 0x73, 0x65, 0x00,
        ];

        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", data, None);
        obj.parse_section(btf_section).unwrap();

        let map_section = fake_section(EbpfSectionKind::BtfMaps, ".maps", &[], None);
        obj.parse_section(map_section).unwrap();

        let map = obj.maps.get("map_1").unwrap();
        assert_matches!(map, Map::Btf(m) => {
            assert_eq!(m.def.key_size, 4);
            assert_eq!(m.def.value_size, 8);
            assert_eq!(m.def.max_entries, 1);
        });
    }
}
