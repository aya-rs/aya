pub(crate) mod btf;
mod relocation;

use log::debug;
use object::{
    read::{Object as ElfObject, ObjectSection, Section as ObjSection},
    Endianness, ObjectSymbol, ObjectSymbolTable, RelocationTarget, SectionIndex, SectionKind,
    SymbolKind,
};
use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    mem, ptr,
    str::FromStr,
};
use thiserror::Error;

use relocation::*;

use crate::{
    bpf_map_def,
    generated::{bpf_insn, bpf_map_info, bpf_map_type::BPF_MAP_TYPE_ARRAY, BPF_F_RDONLY_PROG},
    obj::btf::{Btf, BtfError, BtfExt, BtfType},
    programs::{CgroupSockAddrAttachType, CgroupSockAttachType, CgroupSockoptAttachType},
    BpfError, BtfMapDef, PinningType,
};
use std::slice::from_raw_parts_mut;

use self::btf::{Array, DataSecEntry, FuncSecInfo, LineSecInfo};

const KERNEL_VERSION_ANY: u32 = 0xFFFF_FFFE;
/// The first five __u32 of `bpf_map_def` must be defined.
const MINIMUM_MAP_SIZE: usize = mem::size_of::<u32>() * 5;

#[derive(Clone)]
pub struct Object {
    pub(crate) endianness: Endianness,
    pub license: CString,
    pub kernel_version: KernelVersion,
    pub btf: Option<Btf>,
    pub btf_ext: Option<BtfExt>,
    pub(crate) maps: HashMap<String, Map>,
    pub(crate) programs: HashMap<String, Program>,
    pub(crate) functions: HashMap<u64, Function>,
    pub(crate) relocations: HashMap<SectionIndex, HashMap<u64, Relocation>>,
    pub(crate) symbols_by_index: HashMap<usize, Symbol>,
    pub(crate) section_sizes: HashMap<String, u64>,
    // symbol_offset_by_name caches symbols that could be referenced from a
    // BTF VAR type so the offsets can be fixed up
    pub(crate) symbol_offset_by_name: HashMap<String, u64>,
    pub(crate) text_section_index: Option<usize>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum MapKind {
    Bss,
    Data,
    Rodata,
    Other,
}

impl From<&str> for MapKind {
    fn from(s: &str) -> Self {
        if s == ".bss" {
            MapKind::Bss
        } else if s.starts_with(".data") {
            MapKind::Data
        } else if s.starts_with(".rodata") {
            MapKind::Rodata
        } else {
            MapKind::Other
        }
    }
}

#[derive(Debug, Clone)]
pub enum Map {
    Legacy(LegacyMap),
    Btf(BtfMap),
}

impl Map {
    pub(crate) fn map_type(&self) -> u32 {
        match self {
            Map::Legacy(m) => m.def.map_type,
            Map::Btf(m) => m.def.map_type,
        }
    }

    pub(crate) fn key_size(&self) -> u32 {
        match self {
            Map::Legacy(m) => m.def.key_size,
            Map::Btf(m) => m.def.key_size,
        }
    }

    pub(crate) fn value_size(&self) -> u32 {
        match self {
            Map::Legacy(m) => m.def.value_size,
            Map::Btf(m) => m.def.value_size,
        }
    }

    pub(crate) fn max_entries(&self) -> u32 {
        match self {
            Map::Legacy(m) => m.def.max_entries,
            Map::Btf(m) => m.def.max_entries,
        }
    }

    pub(crate) fn set_max_entries(&mut self, v: u32) {
        match self {
            Map::Legacy(m) => m.def.max_entries = v,
            Map::Btf(m) => m.def.max_entries = v,
        }
    }

    pub(crate) fn map_flags(&self) -> u32 {
        match self {
            Map::Legacy(m) => m.def.map_flags,
            Map::Btf(m) => m.def.map_flags,
        }
    }

    pub(crate) fn pinning(&self) -> PinningType {
        match self {
            Map::Legacy(m) => m.def.pinning,
            Map::Btf(m) => m.def.pinning,
        }
    }

    pub(crate) fn data(&self) -> &[u8] {
        match self {
            Map::Legacy(m) => &m.data,
            Map::Btf(m) => &m.data,
        }
    }

    pub(crate) fn data_mut(&mut self) -> &mut Vec<u8> {
        match self {
            Map::Legacy(m) => m.data.as_mut(),
            Map::Btf(m) => m.data.as_mut(),
        }
    }

    pub(crate) fn kind(&self) -> MapKind {
        match self {
            Map::Legacy(m) => m.kind,
            Map::Btf(m) => m.kind,
        }
    }

    pub(crate) fn section_index(&self) -> usize {
        match self {
            Map::Legacy(m) => m.section_index,
            Map::Btf(m) => m.section_index,
        }
    }

    pub(crate) fn symbol_index(&self) -> usize {
        match self {
            Map::Legacy(m) => m.symbol_index,
            Map::Btf(m) => m.symbol_index,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LegacyMap {
    pub(crate) def: bpf_map_def,
    pub(crate) section_index: usize,
    pub(crate) symbol_index: usize,
    pub(crate) data: Vec<u8>,
    pub(crate) kind: MapKind,
}

#[derive(Debug, Clone)]
pub struct BtfMap {
    pub(crate) def: BtfMapDef,
    pub(crate) section_index: usize,
    pub(crate) symbol_index: usize,
    pub(crate) kind: MapKind,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct Program {
    pub(crate) license: CString,
    pub(crate) kernel_version: KernelVersion,
    pub(crate) section: ProgramSection,
    pub(crate) function: Function,
}

#[derive(Debug, Clone)]
pub(crate) struct Function {
    pub(crate) address: u64,
    pub(crate) name: String,
    pub(crate) section_index: SectionIndex,
    pub(crate) section_offset: usize,
    pub(crate) instructions: Vec<bpf_insn>,
    pub(crate) func_info: FuncSecInfo,
    pub(crate) line_info: LineSecInfo,
    pub(crate) func_info_rec_size: usize,
    pub(crate) line_info_rec_size: usize,
}

#[derive(Debug, Clone)]
pub enum ProgramSection {
    KRetProbe {
        name: String,
    },
    KProbe {
        name: String,
    },
    UProbe {
        name: String,
    },
    URetProbe {
        name: String,
    },
    TracePoint {
        name: String,
    },
    SocketFilter {
        name: String,
    },
    Xdp {
        name: String,
    },
    SkMsg {
        name: String,
    },
    SkSkbStreamParser {
        name: String,
    },
    SkSkbStreamVerdict {
        name: String,
    },
    SockOps {
        name: String,
    },
    SchedClassifier {
        name: String,
    },
    CgroupSkb {
        name: String,
    },
    CgroupSkbIngress {
        name: String,
    },
    CgroupSkbEgress {
        name: String,
    },
    CgroupSockAddr {
        name: String,
        attach_type: CgroupSockAddrAttachType,
    },
    CgroupSysctl {
        name: String,
    },
    CgroupSockopt {
        name: String,
        attach_type: CgroupSockoptAttachType,
    },
    LircMode2 {
        name: String,
    },
    PerfEvent {
        name: String,
    },
    RawTracePoint {
        name: String,
    },
    Lsm {
        name: String,
    },
    BtfTracePoint {
        name: String,
    },
    FEntry {
        name: String,
    },
    FExit {
        name: String,
    },
    Extension {
        name: String,
    },
    SkLookup {
        name: String,
    },
    CgroupSock {
        name: String,
        attach_type: CgroupSockAttachType,
    },
}

impl ProgramSection {
    fn name(&self) -> &str {
        match self {
            ProgramSection::KRetProbe { name } => name,
            ProgramSection::KProbe { name } => name,
            ProgramSection::UProbe { name } => name,
            ProgramSection::URetProbe { name } => name,
            ProgramSection::TracePoint { name } => name,
            ProgramSection::SocketFilter { name } => name,
            ProgramSection::Xdp { name } => name,
            ProgramSection::SkMsg { name } => name,
            ProgramSection::SkSkbStreamParser { name } => name,
            ProgramSection::SkSkbStreamVerdict { name } => name,
            ProgramSection::SockOps { name } => name,
            ProgramSection::SchedClassifier { name } => name,
            ProgramSection::CgroupSkb { name, .. } => name,
            ProgramSection::CgroupSkbIngress { name, .. } => name,
            ProgramSection::CgroupSkbEgress { name, .. } => name,
            ProgramSection::CgroupSockAddr { name, .. } => name,
            ProgramSection::CgroupSysctl { name } => name,
            ProgramSection::CgroupSockopt { name, .. } => name,
            ProgramSection::LircMode2 { name } => name,
            ProgramSection::PerfEvent { name } => name,
            ProgramSection::RawTracePoint { name } => name,
            ProgramSection::Lsm { name } => name,
            ProgramSection::BtfTracePoint { name } => name,
            ProgramSection::FEntry { name } => name,
            ProgramSection::FExit { name } => name,
            ProgramSection::Extension { name } => name,
            ProgramSection::SkLookup { name } => name,
            ProgramSection::CgroupSock { name, .. } => name,
        }
    }
}

impl FromStr for ProgramSection {
    type Err = ParseError;

    fn from_str(section: &str) -> Result<ProgramSection, ParseError> {
        use ProgramSection::*;

        // parse the common case, eg "xdp/program_name" or
        // "sk_skb/stream_verdict/program_name"
        let mut parts = section.rsplitn(2, '/').collect::<Vec<_>>();
        if parts.len() == 1 {
            parts.push(parts[0]);
        }
        let kind = parts[1];
        let name = parts[0].to_owned();

        Ok(match kind {
            "kprobe" => KProbe { name },
            "kretprobe" => KRetProbe { name },
            "uprobe" => UProbe { name },
            "uretprobe" => URetProbe { name },
            "xdp" => Xdp { name },
            "tp_btf" => BtfTracePoint { name },
            _ if kind.starts_with("tracepoint") || kind.starts_with("tp") => {
                // tracepoint sections are named `tracepoint/category/event_name`,
                // and we want to parse the name as "category/event_name"
                let name = section.splitn(2, '/').last().unwrap().to_owned();
                TracePoint { name }
            }
            "socket" => SocketFilter { name },
            "sk_msg" => SkMsg { name },
            "sk_skb" => match &*name {
                "stream_parser" => SkSkbStreamParser { name },
                "stream_verdict" => SkSkbStreamVerdict { name },
                _ => {
                    return Err(ParseError::InvalidProgramSection {
                        section: section.to_owned(),
                    })
                }
            },
            "sk_skb/stream_parser" => SkSkbStreamParser { name },
            "sk_skb/stream_verdict" => SkSkbStreamVerdict { name },
            "sockops" => SockOps { name },
            "classifier" => SchedClassifier { name },
            "cgroup_skb" => match &*name {
                "ingress" => CgroupSkbIngress { name },
                "egress" => CgroupSkbEgress { name },
                _ => {
                    return Err(ParseError::InvalidProgramSection {
                        section: section.to_owned(),
                    })
                }
            },
            "cgroup_skb/ingress" => CgroupSkbIngress { name },
            "cgroup_skb/egress" => CgroupSkbEgress { name },
            "cgroup/skb" => CgroupSkb { name },
            "cgroup/sock" => CgroupSock {
                name,
                attach_type: CgroupSockAttachType::default(),
            },
            "cgroup/sysctl" => CgroupSysctl { name },
            "cgroup/getsockopt" => CgroupSockopt {
                name,
                attach_type: CgroupSockoptAttachType::Get,
            },
            "cgroup/setsockopt" => CgroupSockopt {
                name,
                attach_type: CgroupSockoptAttachType::Set,
            },
            "cgroup" => match &*name {
                "skb" => CgroupSkb { name },
                "sysctl" => CgroupSysctl { name },
                "getsockopt" | "setsockopt" => {
                    if let Ok(attach_type) = CgroupSockoptAttachType::try_from(name.as_str()) {
                        CgroupSockopt { name, attach_type }
                    } else {
                        return Err(ParseError::InvalidProgramSection {
                            section: section.to_owned(),
                        });
                    }
                }
                "sock" => CgroupSock {
                    name,
                    attach_type: CgroupSockAttachType::default(),
                },
                "post_bind4" | "post_bind6" | "sock_create" | "sock_release" => {
                    if let Ok(attach_type) = CgroupSockAttachType::try_from(name.as_str()) {
                        CgroupSock { name, attach_type }
                    } else {
                        return Err(ParseError::InvalidProgramSection {
                            section: section.to_owned(),
                        });
                    }
                }
                _ => {
                    if let Ok(attach_type) = CgroupSockAddrAttachType::try_from(name.as_str()) {
                        CgroupSockAddr { name, attach_type }
                    } else {
                        return Err(ParseError::InvalidProgramSection {
                            section: section.to_owned(),
                        });
                    }
                }
            },
            "cgroup/post_bind4" => CgroupSock {
                name,
                attach_type: CgroupSockAttachType::PostBind4,
            },
            "cgroup/post_bind6" => CgroupSock {
                name,
                attach_type: CgroupSockAttachType::PostBind6,
            },
            "cgroup/sock_create" => CgroupSock {
                name,
                attach_type: CgroupSockAttachType::SockCreate,
            },
            "cgroup/sock_release" => CgroupSock {
                name,
                attach_type: CgroupSockAttachType::SockRelease,
            },
            "cgroup/bind4" => CgroupSockAddr {
                name,
                attach_type: CgroupSockAddrAttachType::Bind4,
            },
            "cgroup/bind6" => CgroupSockAddr {
                name,
                attach_type: CgroupSockAddrAttachType::Bind6,
            },
            "cgroup/connect4" => CgroupSockAddr {
                name,
                attach_type: CgroupSockAddrAttachType::Connect4,
            },
            "cgroup/connect6" => CgroupSockAddr {
                name,
                attach_type: CgroupSockAddrAttachType::Connect6,
            },
            "cgroup/getpeername4" => CgroupSockAddr {
                name,
                attach_type: CgroupSockAddrAttachType::GetPeerName4,
            },
            "cgroup/getpeername6" => CgroupSockAddr {
                name,
                attach_type: CgroupSockAddrAttachType::GetPeerName6,
            },
            "cgroup/getsockname4" => CgroupSockAddr {
                name,
                attach_type: CgroupSockAddrAttachType::GetSockName4,
            },
            "cgroup/getsockname6" => CgroupSockAddr {
                name,
                attach_type: CgroupSockAddrAttachType::GetSockName6,
            },
            "cgroup/sendmsg4" => CgroupSockAddr {
                name,
                attach_type: CgroupSockAddrAttachType::UDPSendMsg4,
            },
            "cgroup/sendmsg6" => CgroupSockAddr {
                name,
                attach_type: CgroupSockAddrAttachType::UDPSendMsg6,
            },
            "cgroup/recvmsg4" => CgroupSockAddr {
                name,
                attach_type: CgroupSockAddrAttachType::UDPRecvMsg4,
            },
            "cgroup/recvmsg6" => CgroupSockAddr {
                name,
                attach_type: CgroupSockAddrAttachType::UDPRecvMsg6,
            },
            "lirc_mode2" => LircMode2 { name },
            "perf_event" => PerfEvent { name },
            "raw_tp" | "raw_tracepoint" => RawTracePoint { name },
            "lsm" => Lsm { name },
            "fentry" => FEntry { name },
            "fexit" => FExit { name },
            "freplace" => Extension { name },
            "sk_lookup" => SkLookup { name },
            _ => {
                return Err(ParseError::InvalidProgramSection {
                    section: section.to_owned(),
                })
            }
        })
    }
}

impl Object {
    pub(crate) fn parse(data: &[u8]) -> Result<Object, BpfError> {
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
            KernelVersion::Any
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
                bpf_obj.symbols_by_index.insert(symbol.index().0, sym);

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

    fn new(endianness: Endianness, license: CString, kernel_version: KernelVersion) -> Object {
        Object {
            endianness,
            license,
            kernel_version,
            btf: None,
            btf_ext: None,
            maps: HashMap::new(),
            programs: HashMap::new(),
            functions: HashMap::new(),
            relocations: HashMap::new(),
            symbols_by_index: HashMap::new(),
            section_sizes: HashMap::new(),
            symbol_offset_by_name: HashMap::new(),
            text_section_index: None,
        }
    }

    pub fn patch_map_data(&mut self, globals: HashMap<&str, &[u8]>) -> Result<(), ParseError> {
        let symbols: HashMap<String, &Symbol> = self
            .symbols_by_index
            .iter()
            .filter(|(_, s)| s.name.is_some())
            .map(|(_, s)| (s.name.as_ref().unwrap().clone(), s))
            .collect();

        for (name, data) in globals {
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
            } else {
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

    fn parse_program(&self, section: &Section) -> Result<Program, ParseError> {
        let prog_sec = ProgramSection::from_str(section.name)?;
        let name = prog_sec.name().to_owned();

        let (func_info, line_info, func_info_rec_size, line_info_rec_size) =
            if let Some(btf_ext) = &self.btf_ext {
                let func_info = btf_ext.func_info.get(section.name);
                let line_info = btf_ext.line_info.get(section.name);
                (
                    func_info,
                    line_info,
                    btf_ext.func_info_rec_size(),
                    btf_ext.line_info_rec_size(),
                )
            } else {
                (FuncSecInfo::default(), LineSecInfo::default(), 0, 0)
            };

        Ok(Program {
            license: self.license.clone(),
            kernel_version: self.kernel_version,
            section: prog_sec,
            function: Function {
                name,
                address: section.address,
                section_index: section.index,
                section_offset: 0,
                instructions: copy_instructions(section.data)?,
                func_info,
                line_info,
                func_info_rec_size,
                line_info_rec_size,
            },
        })
    }

    fn parse_text_section(&mut self, mut section: Section) -> Result<(), ParseError> {
        self.text_section_index = Some(section.index.0);

        let mut symbols_by_address = HashMap::new();

        for sym in self.symbols_by_index.values() {
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
                if let Some(btf_ext) = &self.btf_ext {
                    let bytes_offset = offset as u32 / INS_SIZE as u32;
                    let section_size_bytes = sym.size as u32 / INS_SIZE as u32;

                    let mut func_info = btf_ext.func_info.get(section.name);
                    func_info.func_info.retain(|f| f.insn_off == bytes_offset);

                    let mut line_info = btf_ext.line_info.get(section.name);
                    line_info.line_info.retain(|l| {
                        l.insn_off >= bytes_offset
                            && l.insn_off < (bytes_offset + section_size_bytes)
                    });

                    (
                        func_info,
                        line_info,
                        btf_ext.func_info_rec_size(),
                        btf_ext.line_info_rec_size(),
                    )
                } else {
                    (FuncSecInfo::default(), LineSecInfo::default(), 0, 0)
                };

            self.functions.insert(
                sym.address,
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
                    .drain(..)
                    .map(|rel| (rel.offset, rel))
                    .collect(),
            );
        }

        Ok(())
    }

    fn parse_map_section(
        &mut self,
        section: &Section,
        symbols: Vec<Symbol>,
    ) -> Result<(), ParseError> {
        if symbols.is_empty() {
            return Err(ParseError::NoSymbolsInMapSection {});
        }
        for (i, sym) in symbols.iter().enumerate() {
            let start = sym.address as usize;
            let end = start + sym.size as usize;
            let data = &section.data[start..end];
            let name = sym
                .name
                .as_ref()
                .ok_or(ParseError::MapSymbolNameNotFound { i })?;
            let def = parse_map_def(name, data)?;
            self.maps.insert(
                name.to_string(),
                Map::Legacy(LegacyMap {
                    section_index: section.index.0,
                    symbol_index: sym.index,
                    def,
                    data: Vec::new(),
                    kind: MapKind::Other,
                }),
            );
        }
        Ok(())
    }

    fn parse_btf_maps(
        &mut self,
        section: &Section,
        symbols: HashMap<String, Symbol>,
    ) -> Result<(), BpfError> {
        if self.btf.is_none() {
            return Err(BpfError::NoBTF);
        }
        let btf = self.btf.as_ref().unwrap();

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
                        let symbol_index = symbols
                            .get(&map_name)
                            .ok_or_else(|| {
                                BpfError::ParseError(ParseError::SymbolNotFound {
                                    name: map_name.to_string(),
                                })
                            })?
                            .index;
                        self.maps.insert(
                            map_name,
                            Map::Btf(BtfMap {
                                def,
                                section_index: section.index.0,
                                symbol_index,
                                kind: MapKind::Other,
                                data: Vec::new(),
                            }),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_section(&mut self, mut section: Section) -> Result<(), BpfError> {
        let mut parts = section.name.rsplitn(2, '/').collect::<Vec<_>>();
        parts.reverse();

        if parts.len() == 1
            && (parts[0] == "xdp"
                || parts[0] == "sk_msg"
                || parts[0] == "sockops"
                || parts[0] == "classifier")
        {
            parts.push(parts[0]);
        }
        self.section_sizes
            .insert(section.name.to_owned(), section.size);
        match section.kind {
            BpfSectionKind::Data => {
                self.maps
                    .insert(section.name.to_string(), parse_map(&section, section.name)?);
            }
            BpfSectionKind::Text => self.parse_text_section(section)?,
            BpfSectionKind::Btf => self.parse_btf(&section)?,
            BpfSectionKind::BtfExt => self.parse_btf_ext(&section)?,
            BpfSectionKind::BtfMaps => {
                let symbols: HashMap<String, Symbol> = self
                    .symbols_by_index
                    .values()
                    .filter(|s| {
                        if let Some(idx) = s.section_index {
                            idx == section.index.0 && s.name.is_some()
                        } else {
                            false
                        }
                    })
                    .cloned()
                    .map(|s| (s.name.as_ref().unwrap().to_string(), s))
                    .collect();
                self.parse_btf_maps(&section, symbols)?
            }
            BpfSectionKind::Maps => {
                let symbols: Vec<Symbol> = self
                    .symbols_by_index
                    .values()
                    .filter(|s| {
                        if let Some(idx) = s.section_index {
                            idx == section.index.0
                        } else {
                            false
                        }
                    })
                    .cloned()
                    .collect();
                self.parse_map_section(&section, symbols)?
            }
            BpfSectionKind::Program => {
                let program = self.parse_program(&section)?;
                self.programs
                    .insert(program.section.name().to_owned(), program);
                if !section.relocations.is_empty() {
                    self.relocations.insert(
                        section.index,
                        section
                            .relocations
                            .drain(..)
                            .map(|rel| (rel.offset, rel))
                            .collect(),
                    );
                }
            }
            BpfSectionKind::Undefined | BpfSectionKind::License | BpfSectionKind::Version => {}
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Error)]
pub enum ParseError {
    #[error("error parsing ELF data")]
    ElfError(#[from] object::read::Error),

    #[error("invalid license `{data:?}`: missing NULL terminator")]
    MissingLicenseNullTerminator { data: Vec<u8> },

    #[error("invalid license `{data:?}`")]
    InvalidLicense { data: Vec<u8> },

    #[error("invalid kernel version `{data:?}`")]
    InvalidKernelVersion { data: Vec<u8> },

    #[error("error parsing section with index {index}")]
    SectionError {
        index: usize,
        #[source]
        source: object::read::Error,
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

    #[error("no symbols found for the maps included in the maps section")]
    NoSymbolsInMapSection {},
}

#[derive(Debug)]
enum BpfSectionKind {
    Undefined,
    Maps,
    BtfMaps,
    Program,
    Data,
    Text,
    Btf,
    BtfExt,
    License,
    Version,
}

impl BpfSectionKind {
    fn from_name(name: &str) -> BpfSectionKind {
        if name.starts_with("license") {
            BpfSectionKind::License
        } else if name.starts_with("version") {
            BpfSectionKind::Version
        } else if name.starts_with("maps") {
            BpfSectionKind::Maps
        } else if name.starts_with(".maps") {
            BpfSectionKind::BtfMaps
        } else if name.starts_with(".text") {
            BpfSectionKind::Text
        } else if name.starts_with(".bss")
            || name.starts_with(".data")
            || name.starts_with(".rodata")
        {
            BpfSectionKind::Data
        } else if name == ".BTF" {
            BpfSectionKind::Btf
        } else if name == ".BTF.ext" {
            BpfSectionKind::BtfExt
        } else {
            BpfSectionKind::Undefined
        }
    }
}

#[derive(Debug)]
struct Section<'a> {
    index: SectionIndex,
    kind: BpfSectionKind,
    address: u64,
    name: &'a str,
    data: &'a [u8],
    size: u64,
    relocations: Vec<Relocation>,
}

impl<'data, 'file, 'a> TryFrom<&'a ObjSection<'data, 'file>> for Section<'a> {
    type Error = ParseError;

    fn try_from(section: &'a ObjSection) -> Result<Section<'a>, ParseError> {
        let index = section.index();
        let map_err = |source| ParseError::SectionError {
            index: index.0,
            source,
        };
        let name = section.name().map_err(map_err)?;
        let kind = match BpfSectionKind::from_name(name) {
            BpfSectionKind::Undefined => {
                if section.kind() == SectionKind::Text && section.size() > 0 {
                    BpfSectionKind::Program
                } else {
                    BpfSectionKind::Undefined
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

fn parse_version(data: &[u8], endianness: object::Endianness) -> Result<KernelVersion, ParseError> {
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

    Ok(match v {
        KERNEL_VERSION_ANY => KernelVersion::Any,
        v => KernelVersion::Version(v),
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KernelVersion {
    Version(u32),
    Any,
}

impl From<KernelVersion> for u32 {
    fn from(version: KernelVersion) -> u32 {
        match version {
            KernelVersion::Any => KERNEL_VERSION_ANY,
            KernelVersion::Version(v) => v,
        }
    }
}

fn parse_map(section: &Section, name: &str) -> Result<Map, ParseError> {
    let kind = MapKind::from(name);
    let (def, data) = match kind {
        MapKind::Bss | MapKind::Data | MapKind::Rodata => {
            let def = bpf_map_def {
                map_type: BPF_MAP_TYPE_ARRAY as u32,
                key_size: mem::size_of::<u32>() as u32,
                // We need to use section.size here since
                // .bss will always have data.len() == 0
                value_size: section.size as u32,
                max_entries: 1,
                map_flags: if kind == MapKind::Rodata {
                    BPF_F_RDONLY_PROG
                } else {
                    0
                },
                ..Default::default()
            };
            (def, section.data.to_vec())
        }
        MapKind::Other => (parse_map_def(name, section.data)?, Vec::new()),
    };
    Ok(Map::Legacy(LegacyMap {
        section_index: section.index.0,
        symbol_index: 0,
        def,
        data,
        kind,
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

pub(crate) fn parse_map_info(info: bpf_map_info, pinned: PinningType) -> Map {
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
            // We should never be loading the .bss or .data or .rodata FDs
            kind: MapKind::Other,
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
            symbol_index: 0,
            data: Vec::new(),
            // We should never be loading the .bss or .data or .rodata FDs
            kind: MapKind::Other,
        })
    }
}

pub(crate) fn copy_instructions(data: &[u8]) -> Result<Vec<bpf_insn>, ParseError> {
    if data.len() % mem::size_of::<bpf_insn>() > 0 {
        return Err(ParseError::InvalidProgramCode);
    }
    let instructions = data
        .chunks_exact(mem::size_of::<bpf_insn>())
        .map(|d| unsafe { ptr::read_unaligned(d.as_ptr() as *const bpf_insn) })
        .collect::<Vec<_>>();
    Ok(instructions)
}

#[cfg(test)]
mod tests {
    use matches::assert_matches;
    use object::Endianness;

    use super::*;
    use crate::PinningType;

    fn fake_section<'a>(kind: BpfSectionKind, name: &'a str, data: &'a [u8]) -> Section<'a> {
        Section {
            index: SectionIndex(0),
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
        let idx = obj.symbols_by_index.len();
        obj.symbols_by_index.insert(
            idx + 1,
            Symbol {
                index: idx + 1,
                section_index: Some(section_index),
                name: Some(name.to_string()),
                address,
                size,
                is_definition: false,
                kind: SymbolKind::Data,
            },
        );
    }

    fn bytes_of<T>(val: &T) -> &[u8] {
        // Safety: This is for testing only
        unsafe { crate::util::bytes_of(val) }
    }

    #[test]
    fn test_parse_generic_error() {
        assert!(matches!(
            Object::parse(&b"foo"[..]),
            Err(BpfError::ParseError(ParseError::ElfError(_)))
        ))
    }

    #[test]
    fn test_parse_license() {
        assert!(matches!(
            parse_license(b""),
            Err(ParseError::InvalidLicense { .. })
        ));

        assert!(matches!(
            parse_license(b"\0"),
            Err(ParseError::InvalidLicense { .. })
        ));

        assert!(matches!(
            parse_license(b"GPL"),
            Err(ParseError::MissingLicenseNullTerminator { .. })
        ));

        assert_eq!(parse_license(b"GPL\0").unwrap().to_str().unwrap(), "GPL");
    }

    #[test]
    fn test_parse_version() {
        assert!(matches!(
            parse_version(b"", Endianness::Little),
            Err(ParseError::InvalidKernelVersion { .. })
        ));

        assert!(matches!(
            parse_version(b"123", Endianness::Little),
            Err(ParseError::InvalidKernelVersion { .. })
        ));

        assert_eq!(
            parse_version(&0xFFFF_FFFEu32.to_le_bytes(), Endianness::Little)
                .expect("failed to parse magic version"),
            KernelVersion::Any
        );

        assert_eq!(
            parse_version(&0xFFFF_FFFEu32.to_be_bytes(), Endianness::Big)
                .expect("failed to parse magic version"),
            KernelVersion::Any
        );

        assert_eq!(
            parse_version(&1234u32.to_le_bytes(), Endianness::Little)
                .expect("failed to parse magic version"),
            KernelVersion::Version(1234)
        );
    }

    #[test]
    fn test_parse_map_def_error() {
        assert!(matches!(
            parse_map_def("foo", &[]),
            Err(ParseError::InvalidMapDefinition { .. })
        ));
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
        };
        let mut buf = [0u8; 128];
        unsafe { ptr::write_unaligned(buf.as_mut_ptr() as *mut _, def) };

        assert_eq!(parse_map_def("foo", &buf).unwrap(), def);
    }

    #[test]
    fn test_parse_map_error() {
        assert!(matches!(
            parse_map(&fake_section(BpfSectionKind::Maps, "maps/foo", &[]), "foo",),
            Err(ParseError::InvalidMapDefinition { .. })
        ));
    }

    #[test]
    fn test_parse_map() {
        assert!(matches!(
            parse_map(
                &fake_section(
                    BpfSectionKind::Maps,
                    "maps/foo",
                    bytes_of(&bpf_map_def {
                        map_type: 1,
                        key_size: 2,
                        value_size: 3,
                        max_entries: 4,
                        map_flags: 5,
                        id: 0,
                        pinning: PinningType::None,
                        ..Default::default()
                    })
                ),
                "foo"
            ),
            Ok(Map::Legacy(LegacyMap{
                section_index: 0,
                def: bpf_map_def {
                    map_type: 1,
                    key_size: 2,
                    value_size: 3,
                    max_entries: 4,
                    map_flags: 5,
                    id: 0,
                    pinning: PinningType::None,
                },
                data,
                ..
            })) if data.is_empty()
        ))
    }

    #[test]
    fn test_parse_map_data() {
        let map_data = b"map data";
        assert!(matches!(
            parse_map(
                &fake_section(
                    BpfSectionKind::Data,
                    ".bss",
                    map_data,
                ),
                ".bss"
            ),
            Ok(Map::Legacy(LegacyMap {
                section_index: 0,
                symbol_index: 0,
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
                kind
            })) if data == map_data && value_size == map_data.len() as u32 && kind == MapKind::Bss
        ))
    }

    fn fake_obj() -> Object {
        Object::new(
            Endianness::Little,
            CString::new("GPL").unwrap(),
            KernelVersion::Any,
        )
    }

    #[test]
    fn test_parse_program_error() {
        let obj = fake_obj();

        assert_matches!(
            obj.parse_program(&fake_section(
                BpfSectionKind::Program,
                "kprobe/foo",
                &42u32.to_ne_bytes(),
            )),
            Err(ParseError::InvalidProgramCode)
        );
    }

    #[test]
    fn test_parse_program() {
        let obj = fake_obj();

        assert_matches!(
            obj.parse_program(&fake_section(BpfSectionKind::Program,"kprobe/foo", bytes_of(&fake_ins()))),
            Ok(Program {
                license,
                kernel_version: KernelVersion::Any,
                section: ProgramSection::KProbe { .. },
                function: Function {
                    name,
                    address: 0,
                    section_index: SectionIndex(0),
                    section_offset: 0,
                    instructions,
                    ..} }) if license.to_string_lossy() == "GPL" && name == "foo" && instructions.len() == 1
        );
    }

    #[test]
    fn test_parse_section_map() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", mem::size_of::<bpf_map_def>() as u64);
        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Maps,
                "maps/foo",
                bytes_of(&bpf_map_def {
                    map_type: 1,
                    key_size: 2,
                    value_size: 3,
                    max_entries: 4,
                    map_flags: 5,
                    ..Default::default()
                })
            )),
            Ok(())
        );
        assert!(obj.maps.get("foo").is_some());
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
        buf.extend(&[0, 0, 0, 0]);
        buf.extend(&map_data);
        assert_matches!(
            obj.parse_section(fake_section(BpfSectionKind::Maps, "maps", buf.as_slice(),)),
            Ok(())
        );
        assert!(obj.maps.get("foo").is_some());
        assert!(obj.maps.get("bar").is_some());
        assert!(obj.maps.get("baz").is_some());
        for map in obj.maps.values() {
            if let Map::Legacy(m) = map {
                assert_eq!(&m.def, def);
            } else {
                panic!("expected a BTF map")
            }
        }
    }

    #[test]
    fn test_parse_section_data() {
        let mut obj = fake_obj();
        assert_matches!(
            obj.parse_section(fake_section(BpfSectionKind::Data, ".bss", b"map data")),
            Ok(())
        );
        assert!(obj.maps.get(".bss").is_some());

        assert_matches!(
            obj.parse_section(fake_section(BpfSectionKind::Data, ".rodata", b"map data")),
            Ok(())
        );
        assert!(obj.maps.get(".rodata").is_some());

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Data,
                ".rodata.boo",
                b"map data"
            )),
            Ok(())
        );
        assert!(obj.maps.get(".rodata.boo").is_some());

        assert_matches!(
            obj.parse_section(fake_section(BpfSectionKind::Data, ".data", b"map data")),
            Ok(())
        );
        assert!(obj.maps.get(".data").is_some());

        assert_matches!(
            obj.parse_section(fake_section(BpfSectionKind::Data, ".data.boo", b"map data")),
            Ok(())
        );
        assert!(obj.maps.get(".data.boo").is_some());
    }

    #[test]
    fn test_parse_section_kprobe() {
        let mut obj = fake_obj();

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "kprobe/foo",
                bytes_of(&fake_ins())
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

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "uprobe/foo",
                bytes_of(&fake_ins())
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
    fn test_parse_section_trace_point() {
        let mut obj = fake_obj();

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "tracepoint/foo",
                bytes_of(&fake_ins())
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
                BpfSectionKind::Program,
                "tp/foo/bar",
                bytes_of(&fake_ins())
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo/bar"),
            Some(Program {
                section: ProgramSection::TracePoint { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_socket_filter() {
        let mut obj = fake_obj();

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "socket/foo",
                bytes_of(&fake_ins())
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

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "xdp/foo",
                bytes_of(&fake_ins())
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::Xdp { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_raw_tp() {
        let mut obj = fake_obj();

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "raw_tp/foo",
                bytes_of(&fake_ins())
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
                BpfSectionKind::Program,
                "raw_tracepoint/bar",
                bytes_of(&fake_ins())
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

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "lsm/foo",
                bytes_of(&fake_ins())
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::Lsm { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_btf_tracepoint() {
        let mut obj = fake_obj();

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "tp_btf/foo",
                bytes_of(&fake_ins())
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

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "sk_skb/stream_parser",
                bytes_of(&fake_ins())
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

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "sk_skb/stream_parser/my_parser",
                bytes_of(&fake_ins())
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

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "fentry/foo",
                bytes_of(&fake_ins())
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
    fn test_parse_section_fexit() {
        let mut obj = fake_obj();

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "fexit/foo",
                bytes_of(&fake_ins())
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
    fn test_parse_section_cgroup_skb_ingress_unnamed() {
        let mut obj = fake_obj();

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "cgroup_skb/ingress",
                bytes_of(&fake_ins())
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

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "cgroup_skb/ingress/foo",
                bytes_of(&fake_ins())
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

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "cgroup/skb",
                bytes_of(&fake_ins())
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

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "cgroup/skb/foo",
                bytes_of(&fake_ins())
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

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "cgroup/connect4/foo",
                bytes_of(&fake_ins())
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

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "cgroup/connect4",
                bytes_of(&fake_ins())
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

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "cgroup/getsockopt/foo",
                bytes_of(&fake_ins())
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

        assert_matches!(
            obj.parse_section(fake_section(
                BpfSectionKind::Program,
                "cgroup/getsockopt",
                bytes_of(&fake_ins())
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
            ".rodata".to_string(),
            Map::Legacy(LegacyMap {
                def: bpf_map_def {
                    map_type: BPF_MAP_TYPE_ARRAY as u32,
                    key_size: mem::size_of::<u32>() as u32,
                    value_size: 3,
                    max_entries: 1,
                    map_flags: BPF_F_RDONLY_PROG,
                    id: 1,
                    pinning: PinningType::None,
                    ..Default::default()
                },
                section_index: 1,
                symbol_index: 1,
                data: vec![0, 0, 0],
                kind: MapKind::Rodata,
            }),
        );
        obj.symbols_by_index.insert(
            1,
            Symbol {
                index: 1,
                section_index: Some(1),
                name: Some("my_config".to_string()),
                address: 0,
                size: 3,
                is_definition: true,
                kind: SymbolKind::Data,
            },
        );

        let test_data: &[u8] = &[1, 2, 3];
        obj.patch_map_data(HashMap::from([("my_config", test_data)]))
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

        let btf_section = fake_section(BpfSectionKind::Btf, ".BTF", data);
        obj.parse_section(btf_section).unwrap();

        let map_section = fake_section(BpfSectionKind::BtfMaps, ".maps", &[]);
        obj.parse_section(map_section).unwrap();

        let map = obj.maps.get("map_1").unwrap();
        if let Map::Btf(m) = map {
            assert_eq!(m.def.key_size, 4);
            assert_eq!(m.def.value_size, 8);
            assert_eq!(m.def.max_entries, 1);
        } else {
            panic!("expected a BTF map")
        }
    }
}
