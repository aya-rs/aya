pub(crate) mod btf;
mod relocation;

use object::{
    read::{Object as ElfObject, ObjectSection, Section as ObjSection},
    Endianness, ObjectSymbol, ObjectSymbolTable, SectionIndex, SymbolIndex,
};
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    ffi::{CStr, CString},
    mem, ptr,
    str::FromStr,
};
use thiserror::Error;

pub use relocation::*;

use crate::{
    bpf_map_def,
    generated::{bpf_insn, bpf_map_type::BPF_MAP_TYPE_ARRAY},
    obj::btf::{Btf, BtfError, BtfExt},
    BpfError,
};

const KERNEL_VERSION_ANY: u32 = 0xFFFF_FFFE;

#[derive(Clone)]
pub struct Object {
    pub(crate) endianness: Endianness,
    pub license: CString,
    pub kernel_version: KernelVersion,
    pub btf: Option<Btf>,
    pub btf_ext: Option<BtfExt>,
    pub(crate) maps: HashMap<String, Map>,
    pub(crate) programs: HashMap<String, Program>,
    pub(crate) relocations: HashMap<SectionIndex, Vec<Relocation>>,
    pub(crate) symbol_table: HashMap<SymbolIndex, Symbol>,
}

#[derive(Debug, Clone)]
pub struct Map {
    pub(crate) name: String,
    pub(crate) def: bpf_map_def,
    pub(crate) section_index: usize,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct Program {
    pub(crate) license: CString,
    pub(crate) kernel_version: KernelVersion,
    pub(crate) instructions: Vec<bpf_insn>,
    pub(crate) kind: ProgramKind,
    pub(crate) section_index: SectionIndex,
}

#[derive(Debug, Copy, Clone)]
pub enum ProgramKind {
    KProbe,
    KRetProbe,
    UProbe,
    URetProbe,
    TracePoint,
    SocketFilter,
    Xdp,
}

impl FromStr for ProgramKind {
    type Err = ParseError;

    fn from_str(kind: &str) -> Result<ProgramKind, ParseError> {
        use ProgramKind::*;
        Ok(match kind {
            "kprobe" => KProbe,
            "kretprobe" => KRetProbe,
            "uprobe" => UProbe,
            "uretprobe" => URetProbe,
            "xdp" => Xdp,
            "trace_point" => TracePoint,
            "socket_filter" => SocketFilter,
            _ => {
                return Err(ParseError::InvalidProgramKind {
                    kind: kind.to_string(),
                })
            }
        })
    }
}

impl Object {
    pub(crate) fn parse(data: &[u8]) -> Result<Object, BpfError> {
        let obj = object::read::File::parse(data).map_err(|e| ParseError::ElfError(e))?;
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

        for s in obj.sections() {
            bpf_obj.parse_section(Section::try_from(&s)?)?;
        }

        if let Some(symbol_table) = obj.symbol_table() {
            for symbol in symbol_table.symbols() {
                bpf_obj.symbol_table.insert(
                    symbol.index(),
                    Symbol {
                        name: symbol.name().ok().map(String::from),
                        section_index: symbol.section().index(),
                        address: symbol.address(),
                    },
                );
            }
        }

        return Ok(bpf_obj);
    }

    fn new(endianness: Endianness, license: CString, kernel_version: KernelVersion) -> Object {
        Object {
            endianness: endianness.into(),
            license,
            kernel_version,
            btf: None,
            btf_ext: None,
            maps: HashMap::new(),
            programs: HashMap::new(),
            relocations: HashMap::new(),
            symbol_table: HashMap::new(),
        }
    }

    fn parse_program(&self, section: &Section, ty: &str) -> Result<Program, ParseError> {
        let num_instructions = section.data.len() / mem::size_of::<bpf_insn>();
        if section.data.len() % mem::size_of::<bpf_insn>() > 0 {
            return Err(ParseError::InvalidProgramCode);
        }
        let instructions = (0..num_instructions)
            .map(|i| unsafe {
                ptr::read_unaligned(
                    (section.data.as_ptr() as usize + i * mem::size_of::<bpf_insn>())
                        as *const bpf_insn,
                )
            })
            .collect::<Vec<_>>();

        Ok(Program {
            section_index: section.index,
            license: self.license.clone(),
            kernel_version: self.kernel_version,
            instructions,
            kind: ProgramKind::from_str(ty)?,
        })
    }

    fn parse_btf(&mut self, section: &Section) -> Result<(), BtfError> {
        self.btf = Some(Btf::parse(section.data, self.endianness)?);

        Ok(())
    }

    fn parse_btf_ext(&mut self, section: &Section) -> Result<(), BtfError> {
        self.btf_ext = Some(BtfExt::parse(section.data, self.endianness)?);
        Ok(())
    }

    fn parse_section(&mut self, section: Section) -> Result<(), BpfError> {
        let parts = section.name.split("/").collect::<Vec<_>>();

        match parts.as_slice() {
            &[name]
                if name == ".bss" || name.starts_with(".data") || name.starts_with(".rodata") =>
            {
                self.maps
                    .insert(name.to_string(), parse_map(&section, name)?);
            }
            &[".BTF"] => self.parse_btf(&section)?,
            &[".BTF.ext"] => self.parse_btf_ext(&section)?,
            &["maps", name] => {
                self.maps
                    .insert(name.to_string(), parse_map(&section, name)?);
            }
            &[ty @ "kprobe", name]
            | &[ty @ "kretprobe", name]
            | &[ty @ "uprobe", name]
            | &[ty @ "uretprobe", name]
            | &[ty @ "socket_filter", name]
            | &[ty @ "xdp", name]
            | &[ty @ "trace_point", name] => {
                self.programs
                    .insert(name.to_string(), self.parse_program(&section, ty)?);
                if !section.relocations.is_empty() {
                    self.relocations.insert(section.index, section.relocations);
                }
            }

            _ => {}
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

    #[error("unsupported relocation")]
    UnsupportedRelocationKind,

    #[error("invalid program kind `{kind}`")]
    InvalidProgramKind { kind: String },

    #[error("invalid program code")]
    InvalidProgramCode,

    #[error("error parsing map `{name}`")]
    InvalidMapDefinition { name: String },
}

struct Section<'a> {
    index: SectionIndex,
    name: &'a str,
    data: &'a [u8],
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
        Ok(Section {
            index,
            name: section.name().map_err(map_err)?,
            data: section.data().map_err(map_err)?,
            relocations: section
                .relocations()
                .map(|(offset, r)| {
                    Ok::<_, ParseError>(Relocation {
                        kind: r.kind(),
                        target: r.target(),
                        addend: r.addend(),
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

#[derive(Copy, Clone, Debug, PartialEq)]
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
    let (def, data) = if name == ".bss" || name.starts_with(".data") || name.starts_with(".rodata")
    {
        let def = bpf_map_def {
            map_type: BPF_MAP_TYPE_ARRAY,
            key_size: mem::size_of::<u32>() as u32,
            value_size: section.data.len() as u32,
            max_entries: 1,
            map_flags: 0, /* FIXME: set rodata readonly */
        };
        (def, section.data.to_vec())
    } else {
        (parse_map_def(name, section.data)?, Vec::new())
    };

    Ok(Map {
        section_index: section.index.0,
        name: name.to_string(),
        def,
        data,
    })
}

fn parse_map_def(name: &str, data: &[u8]) -> Result<bpf_map_def, ParseError> {
    if mem::size_of::<bpf_map_def>() > data.len() {
        return Err(ParseError::InvalidMapDefinition {
            name: name.to_owned(),
        });
    }

    Ok(unsafe { ptr::read_unaligned(data.as_ptr() as *const bpf_map_def) })
}

#[cfg(test)]
mod tests {
    use matches::assert_matches;
    use object::Endianness;
    use std::slice;

    use super::*;

    fn fake_section<'a>(name: &'a str, data: &'a [u8]) -> Section<'a> {
        Section {
            index: SectionIndex(0),
            name,
            data,
            relocations: Vec::new(),
        }
    }

    fn fake_ins() -> bpf_insn {
        bpf_insn {
            code: 0,
            _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
            off: 0,
            imm: 0,
        }
    }

    fn bytes_of<T>(val: &T) -> &[u8] {
        let size = mem::size_of::<T>();
        unsafe { slice::from_raw_parts(slice::from_ref(val).as_ptr().cast(), size) }
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
    fn test_parse_map_def() {
        assert!(matches!(
            parse_map_def("foo", &[]),
            Err(ParseError::InvalidMapDefinition { .. })
        ));
        assert!(matches!(
            parse_map_def(
                "foo",
                bytes_of(&bpf_map_def {
                    map_type: 1,
                    key_size: 2,
                    value_size: 3,
                    max_entries: 4,
                    map_flags: 5
                })
            ),
            Ok(bpf_map_def {
                map_type: 1,
                key_size: 2,
                value_size: 3,
                max_entries: 4,
                map_flags: 5
            })
        ));
    }

    #[test]
    fn test_parse_map_error() {
        assert!(matches!(
            parse_map(&fake_section("maps/foo", &[]), "foo"),
            Err(ParseError::InvalidMapDefinition { .. })
        ))
    }

    #[test]
    fn test_parse_map() {
        assert!(matches!(
            parse_map(
                &fake_section(
                    "maps/foo",
                    bytes_of(&bpf_map_def {
                        map_type: 1,
                        key_size: 2,
                        value_size: 3,
                        max_entries: 4,
                        map_flags: 5
                    })
                ),
                "foo"
            ),
            Ok(Map {
                section_index: 0,
                name,
                def: bpf_map_def {
                    map_type: 1,
                    key_size: 2,
                    value_size: 3,
                    max_entries: 4,
                    map_flags: 5,
                },
                data
            }) if name == "foo" && data.is_empty()
        ))
    }

    #[test]
    fn test_parse_map_data() {
        let map_data = b"map data";
        assert!(matches!(
            parse_map(
                &fake_section(
                    ".bss",
                    map_data,
                ),
                ".bss"
            ),
            Ok(Map {
                section_index: 0,
                name,
                def: bpf_map_def {
                    map_type: BPF_MAP_TYPE_ARRAY,
                    key_size: 4,
                    value_size,
                    max_entries: 1,
                    map_flags: 0,
                },
                data
            }) if name == ".bss" && data == map_data && value_size == map_data.len() as u32
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
            obj.parse_program(&fake_section("kprobe/foo", &42u32.to_ne_bytes(),), "kprobe"),
            Err(ParseError::InvalidProgramCode)
        );
    }

    #[test]
    fn test_parse_program() {
        let obj = fake_obj();

        assert_matches!(
            obj.parse_program(&fake_section("kprobe/foo", bytes_of(&fake_ins())), "kprobe"),
            Ok(Program {
                license,
                kernel_version,
                kind: ProgramKind::KProbe,
                section_index: SectionIndex(0),
                instructions
            }) if license.to_string_lossy() == "GPL" && kernel_version == KernelVersion::Any && instructions.len() == 1
        );
    }

    #[test]
    fn test_parse_section_map() {
        let mut obj = fake_obj();

        assert_matches!(
            obj.parse_section(fake_section(
                "maps/foo",
                bytes_of(&bpf_map_def {
                    map_type: 1,
                    key_size: 2,
                    value_size: 3,
                    max_entries: 4,
                    map_flags: 5
                })
            ),),
            Ok(())
        );
        assert!(obj.maps.get("foo").is_some());
    }

    #[test]
    fn test_parse_section_data() {
        let mut obj = fake_obj();
        assert_matches!(
            obj.parse_section(fake_section(".bss", b"map data"),),
            Ok(())
        );
        assert!(obj.maps.get(".bss").is_some());

        assert_matches!(
            obj.parse_section(fake_section(".rodata", b"map data"),),
            Ok(())
        );
        assert!(obj.maps.get(".rodata").is_some());

        assert_matches!(
            obj.parse_section(fake_section(".rodata.boo", b"map data"),),
            Ok(())
        );
        assert!(obj.maps.get(".rodata.boo").is_some());

        assert_matches!(
            obj.parse_section(fake_section(".data", b"map data"),),
            Ok(())
        );
        assert!(obj.maps.get(".data").is_some());

        assert_matches!(
            obj.parse_section(fake_section(".data.boo", b"map data"),),
            Ok(())
        );
        assert!(obj.maps.get(".data.boo").is_some());
    }

    #[test]
    fn test_parse_section_kprobe() {
        let mut obj = fake_obj();

        assert_matches!(
            obj.parse_section(fake_section("kprobe/foo", bytes_of(&fake_ins()))),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                kind: ProgramKind::KProbe,
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_uprobe() {
        let mut obj = fake_obj();

        assert_matches!(
            obj.parse_section(fake_section("uprobe/foo", bytes_of(&fake_ins()))),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                kind: ProgramKind::UProbe,
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_trace_point() {
        let mut obj = fake_obj();

        assert_matches!(
            obj.parse_section(fake_section("trace_point/foo", bytes_of(&fake_ins()))),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                kind: ProgramKind::TracePoint,
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_socket_filter() {
        let mut obj = fake_obj();

        assert_matches!(
            obj.parse_section(fake_section("socket_filter/foo", bytes_of(&fake_ins()))),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                kind: ProgramKind::SocketFilter,
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_xdp() {
        let mut obj = fake_obj();

        assert_matches!(
            obj.parse_section(fake_section("xdp/foo", bytes_of(&fake_ins()))),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                kind: ProgramKind::Xdp,
                ..
            })
        );
    }
}
