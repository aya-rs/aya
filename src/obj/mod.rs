mod relocation;

use object::{
    pod,
    read::{Object as ElfObject, ObjectSection, Section},
    Endianness, ObjectSymbol, ObjectSymbolTable, SectionIndex, SymbolIndex,
};
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    ffi::{CStr, CString},
    mem,
    str::FromStr,
};
use thiserror::Error;

pub use self::relocation::{relocate, RelocationError};

use crate::{
    bpf_map_def,
    generated::{bpf_insn, bpf_map_type::BPF_MAP_TYPE_ARRAY},
    obj::relocation::{Relocation, Symbol},
};

const KERNEL_VERSION_ANY: u32 = 0xFFFF_FFFE;

#[derive(Debug, Clone)]
pub struct Object {
    pub(crate) endianness: Endianness,
    pub license: CString,
    pub kernel_version: KernelVersion,
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
    UProbe,
    Xdp,
    TracePoint,
}

impl FromStr for ProgramKind {
    type Err = ParseError;

    fn from_str(kind: &str) -> Result<ProgramKind, ParseError> {
        use ProgramKind::*;
        Ok(match kind {
            "kprobe" => KProbe,
            "uprobe" => UProbe,
            "xdp" => Xdp,
            "trace_point" => TracePoint,
            _ => {
                return Err(ParseError::InvalidProgramKind {
                    kind: kind.to_string(),
                })
            }
        })
    }
}

impl Object {
    pub(crate) fn parse(data: &[u8]) -> Result<Object, ParseError> {
        let obj = object::read::File::parse(data).map_err(|source| ParseError::Error { source })?;
        let endianness = obj.endianness();

        let section = obj
            .section_by_name("license")
            .ok_or(ParseError::MissingLicense)?;
        let license = parse_license(BPFSection::try_from(&section)?.data)?;

        let section = obj
            .section_by_name("version")
            .ok_or(ParseError::MissingKernelVersion)?;
        let kernel_version = parse_version(BPFSection::try_from(&section)?.data, endianness)?;

        let mut bpf_obj = Object {
            endianness: endianness.into(),
            license,
            kernel_version,
            maps: HashMap::new(),
            programs: HashMap::new(),
            relocations: HashMap::new(),
            symbol_table: HashMap::new(),
        };

        for s in obj.sections() {
            parse_section(&mut bpf_obj, BPFSection::try_from(&s)?)?;
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
}

#[derive(Debug, Clone, Error)]
pub enum ParseError {
    #[error("error parsing ELF data")]
    Error {
        #[source]
        source: object::read::Error,
    },

    #[error("no license specified")]
    MissingLicense,

    #[error("invalid license `{data:?}`: missing NULL terminator")]
    MissingLicenseNullTerminator { data: Vec<u8> },

    #[error("invalid license `{data:?}`")]
    InvalidLicense { data: Vec<u8> },

    #[error("missing kernel version")]
    MissingKernelVersion,

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

    #[error("error parsing program `{name}`")]
    InvalidProgramCode { name: String },

    #[error("error parsing map `{name}`")]
    InvalidMapDefinition { name: String },
}

struct BPFSection<'s> {
    index: SectionIndex,
    name: &'s str,
    data: &'s [u8],
    relocations: Vec<Relocation>,
}

impl<'data, 'file, 's> TryFrom<&'s Section<'data, 'file>> for BPFSection<'s> {
    type Error = ParseError;

    fn try_from(section: &'s Section) -> Result<BPFSection<'s>, ParseError> {
        let index = section.index();
        let map_err = |source| ParseError::SectionError {
            index: index.0,
            source,
        };
        Ok(BPFSection {
            index,
            name: section.name().map_err(map_err)?,
            data: section.data().map_err(map_err)?,
            relocations: section
                .relocations()
                .map(|(offset, r)| {
                    Ok(Relocation {
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

fn parse_map(section: &BPFSection, name: &str) -> Result<Map, ParseError> {
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
    let (def, rest) =
        pod::from_bytes::<bpf_map_def>(data).map_err(|_| ParseError::InvalidMapDefinition {
            name: name.to_string(),
        })?;
    if !rest.is_empty() {
        return Err(ParseError::InvalidMapDefinition {
            name: name.to_string(),
        });
    }

    Ok(*def)
}

fn parse_program(bpf: &Object, section: &BPFSection, ty: &str) -> Result<Program, ParseError> {
    let (code, rest) = pod::slice_from_bytes::<bpf_insn>(
        section.data,
        section.data.len() / mem::size_of::<bpf_insn>(),
    )
    .map_err(|_| ParseError::InvalidProgramCode {
        name: section.name.to_string(),
    })?;

    if !rest.is_empty() {
        return Err(ParseError::InvalidProgramCode {
            name: section.name.to_string(),
        });
    }

    Ok(Program {
        section_index: section.index,
        license: bpf.license.clone(),
        kernel_version: bpf.kernel_version,
        instructions: code.to_vec(),
        kind: ProgramKind::from_str(ty)?,
    })
}

fn parse_section(bpf: &mut Object, section: BPFSection) -> Result<(), ParseError> {
    let parts = section.name.split("/").collect::<Vec<_>>();

    match parts.as_slice() {
        &[name] if name == ".bss" || name.starts_with(".data") || name.starts_with(".rodata") => {
            bpf.maps
                .insert(name.to_string(), parse_map(&section, name)?);
        }
        &["maps", name] => {
            bpf.maps
                .insert(name.to_string(), parse_map(&section, name)?);
        }
        &[ty @ "kprobe", name]
        | &[ty @ "uprobe", name]
        | &[ty @ "xdp", name]
        | &[ty @ "trace_point", name] => {
            bpf.programs
                .insert(name.to_string(), parse_program(bpf, &section, ty)?);
            if !section.relocations.is_empty() {
                bpf.relocations.insert(section.index, section.relocations);
            }
        }

        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::Endianness;

    #[test]
    fn test_parse_generic_error() {
        assert!(matches!(
            Object::parse(&b"foo"[..]),
            Err(ParseError::Error { .. })
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
}
