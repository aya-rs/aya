use core::{ffi::CStr, mem, ptr};

use alloc::{
    borrow::Cow,
    ffi::CString,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use bytes::BufMut;

use log::debug;
use object::Endianness;

use crate::{
    btf::{
        info::{FuncSecInfo, LineSecInfo},
        relocation::Relocation,
        Array, BtfEnum, BtfKind, BtfMember, BtfType, Const, Enum, FuncInfo, FuncLinkage, Int,
        IntEncoding, LineInfo, Struct, Typedef, VarLinkage,
    },
    generated::{btf_ext_header, btf_header},
    util::{bytes_of, HashMap},
    Object,
};

#[cfg(not(feature = "std"))]
use crate::std;

pub(crate) const MAX_RESOLVE_DEPTH: u8 = 32;
pub(crate) const MAX_SPEC_LEN: usize = 64;

/// The error type returned when `BTF` operations fail.
#[derive(thiserror::Error, Debug)]
pub enum BtfError {
    #[cfg(feature = "std")]
    /// Error parsing file
    #[error("error parsing {path}")]
    FileError {
        /// file path
        path: std::path::PathBuf,
        /// source of the error
        #[source]
        error: std::io::Error,
    },

    /// Error parsing BTF header
    #[error("error parsing BTF header")]
    InvalidHeader,

    /// invalid BTF type info segment
    #[error("invalid BTF type info segment")]
    InvalidTypeInfo,

    /// invalid BTF relocation info segment
    #[error("invalid BTF relocation info segment")]
    InvalidRelocationInfo,

    /// invalid BTF type kind
    #[error("invalid BTF type kind `{kind}`")]
    InvalidTypeKind {
        /// type kind
        kind: u32,
    },

    /// invalid BTF relocation kind
    #[error("invalid BTF relocation kind `{kind}`")]
    InvalidRelocationKind {
        /// type kind
        kind: u32,
    },

    /// invalid BTF string offset
    #[error("invalid BTF string offset: {offset}")]
    InvalidStringOffset {
        /// offset
        offset: usize,
    },

    /// invalid BTF info
    #[error("invalid BTF info, offset: {offset} len: {len} section_len: {section_len}")]
    InvalidInfo {
        /// offset
        offset: usize,
        /// length
        len: usize,
        /// section length
        section_len: usize,
    },

    /// invalid BTF line infos
    #[error("invalid BTF line info, offset: {offset} len: {len} section_len: {section_len}")]
    InvalidLineInfo {
        /// offset
        offset: usize,
        /// length
        len: usize,
        /// section length
        section_len: usize,
    },

    /// unknown BTF type id
    #[error("Unknown BTF type id `{type_id}`")]
    UnknownBtfType {
        /// type id
        type_id: u32,
    },

    /// unexpected btf type id
    #[error("Unexpected BTF type id `{type_id}`")]
    UnexpectedBtfType {
        /// type id
        type_id: u32,
    },

    /// unknown BTF type
    #[error("Unknown BTF type `{type_name}`")]
    UnknownBtfTypeName {
        /// type name
        type_name: String,
    },

    /// maximum depth reached resolving BTF type
    #[error("maximum depth reached resolving BTF type")]
    MaximumTypeDepthReached {
        /// type id
        type_id: u32,
    },

    #[cfg(feature = "std")]
    /// Loading the btf failed
    #[error("the BPF_BTF_LOAD syscall failed. Verifier output: {verifier_log}")]
    LoadError {
        /// The [`std::io::Error`] returned by the `BPF_BTF_LOAD` syscall.
        #[source]
        io_error: std::io::Error,
        /// The error log produced by the kernel verifier.
        verifier_log: String,
    },

    /// offset not found for symbol
    #[error("Offset not found for symbol `{symbol_name}`")]
    SymbolOffsetNotFound {
        /// name of the symbol
        symbol_name: String,
    },

    /// btf type that is not VAR found in DATASEC
    #[error("BTF type that is not VAR was found in DATASEC")]
    InvalidDatasec,

    /// unable to determine the size of section
    #[error("Unable to determine the size of section `{section_name}`")]
    UnknownSectionSize {
        /// name of the section
        section_name: String,
    },

    /// unable to get symbol name
    #[error("Unable to get symbol name")]
    InvalidSymbolName,
}

/// Available BTF features
#[derive(Default, Debug)]
#[allow(missing_docs)]
pub struct BtfFeatures {
    pub btf_func: bool,
    pub btf_func_global: bool,
    pub btf_datasec: bool,
    pub btf_float: bool,
    pub btf_decl_tag: bool,
    pub btf_type_tag: bool,
}

/// Bpf Type Format metadata.
///
/// BTF is a kind of debug metadata that allows eBPF programs compiled against one kernel version
/// to be loaded into different kernel versions.
///
/// Aya automatically loads BTF metadata if you use `Bpf::load_file`. You
/// only need to explicitly use this type if you want to load BTF from a non-standard
/// location or if you are using `Bpf::load`.
#[derive(Clone, Debug)]
pub struct Btf {
    header: btf_header,
    strings: Vec<u8>,
    types: BtfTypes,
    _endianness: Endianness,
}

impl Btf {
    /// Creates a new empty instance with its header initialized
    pub fn new() -> Btf {
        Btf {
            header: btf_header {
                magic: 0xeb9f,
                version: 0x01,
                flags: 0x00,
                hdr_len: 0x18,
                type_off: 0x00,
                type_len: 0x00,
                str_off: 0x00,
                str_len: 0x00,
            },
            strings: vec![0],
            types: BtfTypes::default(),
            _endianness: Endianness::default(),
        }
    }

    pub(crate) fn types(&self) -> impl Iterator<Item = &BtfType> {
        self.types.types.iter()
    }

    /// Adds a string to BTF metadata, returning an offset
    pub fn add_string(&mut self, name: String) -> u32 {
        let str = CString::new(name).unwrap();
        let name_offset = self.strings.len();
        self.strings.extend(str.as_c_str().to_bytes_with_nul());
        self.header.str_len = self.strings.len() as u32;
        name_offset as u32
    }

    /// Adds a type to BTF metadata, returning a type id
    pub fn add_type(&mut self, btf_type: BtfType) -> u32 {
        let size = btf_type.type_info_size() as u32;
        let type_id = self.types.len();
        self.types.push(btf_type);
        self.header.type_len += size;
        self.header.str_off += size;
        type_id as u32
    }

    /// Loads BTF metadata from `/sys/kernel/btf/vmlinux`.
    #[cfg(feature = "std")]
    pub fn from_sys_fs() -> Result<Btf, BtfError> {
        Btf::parse_file("/sys/kernel/btf/vmlinux", Endianness::default())
    }

    /// Loads BTF metadata from the given `path`.
    #[cfg(feature = "std")]
    pub fn parse_file<P: AsRef<std::path::Path>>(
        path: P,
        endianness: Endianness,
    ) -> Result<Btf, BtfError> {
        use std::{borrow::ToOwned, fs};
        let path = path.as_ref();
        Btf::parse(
            &fs::read(path).map_err(|error| BtfError::FileError {
                path: path.to_owned(),
                error,
            })?,
            endianness,
        )
    }

    /// Parses BTF from binary data of the given endianness
    pub fn parse(data: &[u8], endianness: Endianness) -> Result<Btf, BtfError> {
        if data.len() < mem::size_of::<btf_header>() {
            return Err(BtfError::InvalidHeader);
        }

        // safety: btf_header is POD so read_unaligned is safe
        let header = unsafe { read_btf_header(data) };

        let str_off = header.hdr_len as usize + header.str_off as usize;
        let str_len = header.str_len as usize;
        if str_off + str_len > data.len() {
            return Err(BtfError::InvalidHeader);
        }

        let strings = data[str_off..str_off + str_len].to_vec();
        let types = Btf::read_type_info(&header, data, endianness)?;

        Ok(Btf {
            header,
            strings,
            types,
            _endianness: endianness,
        })
    }

    fn read_type_info(
        header: &btf_header,
        data: &[u8],
        endianness: Endianness,
    ) -> Result<BtfTypes, BtfError> {
        let hdr_len = header.hdr_len as usize;
        let type_off = header.type_off as usize;
        let type_len = header.type_len as usize;
        let base = hdr_len + type_off;
        if base + type_len > data.len() {
            return Err(BtfError::InvalidTypeInfo);
        }

        let mut data = &data[base..base + type_len];
        let mut types = BtfTypes::default();
        while !data.is_empty() {
            // Safety:
            // read() reads POD values from ELF, which is sound, but the values can still contain
            // internally inconsistent values (like out of bound offsets and such).
            let ty = unsafe { BtfType::read(data, endianness)? };
            data = &data[ty.type_info_size()..];
            types.push(ty);
        }
        Ok(types)
    }

    pub(crate) fn string_at(&self, offset: u32) -> Result<Cow<'_, str>, BtfError> {
        let btf_header {
            hdr_len,
            mut str_off,
            str_len,
            ..
        } = self.header;
        str_off += hdr_len;
        if offset >= str_off + str_len {
            return Err(BtfError::InvalidStringOffset {
                offset: offset as usize,
            });
        }

        let offset = offset as usize;
        let nul = self.strings[offset..]
            .iter()
            .position(|c| *c == 0u8)
            .ok_or(BtfError::InvalidStringOffset { offset })?;

        let s = CStr::from_bytes_with_nul(&self.strings[offset..=offset + nul])
            .map_err(|_| BtfError::InvalidStringOffset { offset })?;

        Ok(s.to_string_lossy())
    }

    pub(crate) fn type_by_id(&self, type_id: u32) -> Result<&BtfType, BtfError> {
        self.types.type_by_id(type_id)
    }

    pub(crate) fn resolve_type(&self, root_type_id: u32) -> Result<u32, BtfError> {
        self.types.resolve_type(root_type_id)
    }

    pub(crate) fn type_name(&self, ty: &BtfType) -> Result<Cow<'_, str>, BtfError> {
        self.string_at(ty.name_offset())
    }

    pub(crate) fn err_type_name(&self, ty: &BtfType) -> Option<String> {
        self.string_at(ty.name_offset()).ok().map(String::from)
    }

    /// Returns a type id matching the type name and [BtfKind]
    pub fn id_by_type_name_kind(&self, name: &str, kind: BtfKind) -> Result<u32, BtfError> {
        for (type_id, ty) in self.types().enumerate() {
            if ty.kind() != kind {
                continue;
            }
            if self.type_name(ty)? == name {
                return Ok(type_id as u32);
            }
            continue;
        }

        Err(BtfError::UnknownBtfTypeName {
            type_name: name.to_string(),
        })
    }

    pub(crate) fn type_size(&self, root_type_id: u32) -> Result<usize, BtfError> {
        let mut type_id = root_type_id;
        let mut n_elems = 1;
        for _ in 0..MAX_RESOLVE_DEPTH {
            let ty = self.types.type_by_id(type_id)?;
            let size = match ty {
                BtfType::Array(Array { array, .. }) => {
                    n_elems = array.len;
                    type_id = array.element_type;
                    continue;
                }
                other => {
                    if let Some(size) = other.size() {
                        size
                    } else if let Some(next) = other.btf_type() {
                        type_id = next;
                        continue;
                    } else {
                        return Err(BtfError::UnexpectedBtfType { type_id });
                    }
                }
            };
            return Ok((size * n_elems) as usize);
        }

        Err(BtfError::MaximumTypeDepthReached {
            type_id: root_type_id,
        })
    }

    /// Encodes the metadata as BTF format
    pub fn to_bytes(&self) -> Vec<u8> {
        // Safety: btf_header is POD
        let mut buf = unsafe { bytes_of::<btf_header>(&self.header).to_vec() };
        // Skip the first type since it's always BtfType::Unknown for type_by_id to work
        buf.extend(self.types.to_bytes());
        buf.put(self.strings.as_slice());
        buf
    }

    pub(crate) fn fixup_and_sanitize(
        &mut self,
        section_sizes: &HashMap<String, u64>,
        symbol_offsets: &HashMap<String, u64>,
        features: &BtfFeatures,
    ) -> Result<(), BtfError> {
        let mut types = mem::take(&mut self.types);
        for i in 0..types.types.len() {
            let t = &types.types[i];
            let kind = t.kind();
            match t {
                // Fixup PTR for Rust
                // LLVM emits names for Rust pointer types, which the kernel doesn't like
                // While I figure out if this needs fixing in the Kernel or LLVM, we'll
                // do a fixup here
                BtfType::Ptr(ptr) => {
                    let mut fixed_ty = ptr.clone();
                    fixed_ty.name_offset = 0;
                    types.types[i] = BtfType::Ptr(fixed_ty)
                }
                // Sanitize VAR if they are not supported
                BtfType::Var(v) if !features.btf_datasec => {
                    types.types[i] = BtfType::Int(Int::new(v.name_offset, 1, IntEncoding::None, 0));
                }
                // Sanitize DATASEC if they are not supported
                BtfType::DataSec(d) if !features.btf_datasec => {
                    debug!("{}: not supported. replacing with STRUCT", kind);

                    // STRUCT aren't allowed to have "." in their name, fixup this if needed.
                    let mut name_offset = t.name_offset();
                    let sec_name = self.string_at(name_offset)?;
                    let name = sec_name.to_string();

                    // Handle any "." characters in struct names
                    // Example: ".maps"
                    let fixed_name = name.replace('.', "_");
                    if fixed_name != name {
                        name_offset = self.add_string(fixed_name);
                    }

                    let mut members = vec![];
                    for member in d.entries.iter() {
                        let mt = types.type_by_id(member.btf_type).unwrap();
                        members.push(BtfMember {
                            name_offset: mt.name_offset(),
                            btf_type: member.btf_type,
                            offset: member.offset * 8,
                        })
                    }

                    types.types[i] =
                        BtfType::Struct(Struct::new(name_offset, members, d.entries.len() as u32));
                }
                // Fixup DATASEC
                // DATASEC sizes aren't always set by LLVM
                // we need to fix them here before loading the btf to the kernel
                BtfType::DataSec(d) if features.btf_datasec => {
                    // Start DataSec Fixups
                    let sec_name = self.string_at(d.name_offset)?;
                    let name = sec_name.to_string();

                    let mut fixed_ty = d.clone();

                    // Handle any "/" characters in section names
                    // Example: "maps/hashmap"
                    let fixed_name = name.replace('/', ".");
                    if fixed_name != name {
                        fixed_ty.name_offset = self.add_string(fixed_name);
                    }

                    // There are some cases when the compiler does indeed populate the
                    // size
                    if t.size().unwrap() > 0 {
                        debug!("{} {}: size fixup not required", kind, name);
                    } else {
                        // We need to get the size of the section from the ELF file
                        // Fortunately, we cached these when parsing it initially
                        // and we can this up by name in section_sizes
                        let size = section_sizes.get(&name).ok_or_else(|| {
                            BtfError::UnknownSectionSize {
                                section_name: name.clone(),
                            }
                        })?;
                        debug!("{} {}: fixup size to {}", kind, name, size);
                        fixed_ty.size = *size as u32;

                        // The Vec<btf_var_secinfo> contains BTF_KIND_VAR sections
                        // that need to have their offsets adjusted. To do this,
                        // we need to get the offset from the ELF file.
                        // This was also cached during initial parsing and
                        // we can query by name in symbol_offsets
                        for d in &mut fixed_ty.entries.iter_mut() {
                            let var_type = types.type_by_id(d.btf_type)?;
                            let var_kind = var_type.kind();
                            if let BtfType::Var(var) = var_type {
                                let var_name = self.string_at(var.name_offset)?.to_string();
                                if var.linkage == VarLinkage::Static {
                                    debug!(
                                        "{} {}: {} {}: fixup not required",
                                        kind, name, var_kind, var_name
                                    );
                                    continue;
                                }

                                let offset = symbol_offsets.get(&var_name).ok_or(
                                    BtfError::SymbolOffsetNotFound {
                                        symbol_name: var_name.clone(),
                                    },
                                )?;
                                d.offset = *offset as u32;
                                debug!(
                                    "{} {}: {} {}: fixup offset {}",
                                    kind, name, var_kind, var_name, offset
                                );
                            } else {
                                return Err(BtfError::InvalidDatasec);
                            }
                        }
                    }
                    types.types[i] = BtfType::DataSec(fixed_ty);
                }
                // Fixup FUNC_PROTO
                BtfType::FuncProto(ty) if features.btf_func => {
                    let mut ty = ty.clone();
                    for (i, mut param) in ty.params.iter_mut().enumerate() {
                        if param.name_offset == 0 && param.btf_type != 0 {
                            param.name_offset = self.add_string(format!("param{i}"));
                        }
                    }
                    types.types[i] = BtfType::FuncProto(ty);
                }
                // Sanitize FUNC_PROTO
                BtfType::FuncProto(ty) if !features.btf_func => {
                    debug!("{}: not supported. replacing with ENUM", kind);
                    let members: Vec<BtfEnum> = ty
                        .params
                        .iter()
                        .map(|p| BtfEnum {
                            name_offset: p.name_offset,
                            value: p.btf_type,
                        })
                        .collect();
                    let enum_type = BtfType::Enum(Enum::new(ty.name_offset, members));
                    types.types[i] = enum_type;
                }
                // Sanitize FUNC
                BtfType::Func(ty) => {
                    let name = self.string_at(ty.name_offset)?;
                    // Sanitize FUNC
                    if !features.btf_func {
                        debug!("{}: not supported. replacing with TYPEDEF", kind);
                        let typedef_type =
                            BtfType::Typedef(Typedef::new(ty.name_offset, ty.btf_type));
                        types.types[i] = typedef_type;
                    } else if !features.btf_func_global
                        || name == "memset"
                        || name == "memcpy"
                        || name == "memmove"
                        || name == "memcmp"
                    {
                        // Sanitize BTF_FUNC_GLOBAL when not supported and ensure that
                        // memory builtins are marked as static. Globals are type checked
                        // and verified separately from their callers, while instead we
                        // want tracking info (eg bound checks) to be propagated to the
                        // memory builtins.
                        let mut fixed_ty = ty.clone();
                        if ty.linkage() == FuncLinkage::Global {
                            if !features.btf_func_global {
                                debug!(
                                    "{}: BTF_FUNC_GLOBAL not supported. replacing with BTF_FUNC_STATIC",
                                    kind
                                );
                            } else {
                                debug!("changing FUNC {name} linkage to BTF_FUNC_STATIC");
                            }
                            fixed_ty.set_linkage(FuncLinkage::Static);
                        }
                        types.types[i] = BtfType::Func(fixed_ty);
                    }
                }
                // Sanitize FLOAT
                BtfType::Float(ty) if !features.btf_float => {
                    debug!("{}: not supported. replacing with STRUCT", kind);
                    let struct_ty = BtfType::Struct(Struct::new(0, vec![], ty.size));
                    types.types[i] = struct_ty;
                }
                // Sanitize DECL_TAG
                BtfType::DeclTag(ty) if !features.btf_decl_tag => {
                    debug!("{}: not supported. replacing with INT", kind);
                    let int_type = BtfType::Int(Int::new(ty.name_offset, 1, IntEncoding::None, 0));
                    types.types[i] = int_type;
                }
                // Sanitize TYPE_TAG
                BtfType::TypeTag(ty) if !features.btf_type_tag => {
                    debug!("{}: not supported. replacing with CONST", kind);
                    let const_type = BtfType::Const(Const::new(ty.btf_type));
                    types.types[i] = const_type;
                }
                // The type does not need fixing up or sanitization
                _ => {}
            }
        }
        self.types = types;
        Ok(())
    }
}

impl Default for Btf {
    fn default() -> Self {
        Self::new()
    }
}

impl Object {
    /// Fixes up and sanitizes BTF data.
    ///
    /// Mostly, it removes unsupported types and works around LLVM behaviours.
    pub fn fixup_and_sanitize_btf(
        &mut self,
        features: &BtfFeatures,
    ) -> Result<Option<&Btf>, BtfError> {
        if let Some(ref mut obj_btf) = self.btf {
            // fixup btf
            obj_btf.fixup_and_sanitize(
                &self.section_sizes,
                &self.symbol_offset_by_name,
                features,
            )?;
            Ok(Some(obj_btf))
        } else {
            Ok(None)
        }
    }
}

unsafe fn read_btf_header(data: &[u8]) -> btf_header {
    // safety: btf_header is POD so read_unaligned is safe
    ptr::read_unaligned(data.as_ptr() as *const btf_header)
}

/// Data in the `.BTF.ext` section
#[derive(Debug, Clone)]
pub struct BtfExt {
    data: Vec<u8>,
    _endianness: Endianness,
    relocations: Vec<(u32, Vec<Relocation>)>,
    header: btf_ext_header,
    func_info_rec_size: usize,
    pub(crate) func_info: FuncInfo,
    line_info_rec_size: usize,
    pub(crate) line_info: LineInfo,
    core_relo_rec_size: usize,
}

impl BtfExt {
    pub(crate) fn parse(
        data: &[u8],
        endianness: Endianness,
        btf: &Btf,
    ) -> Result<BtfExt, BtfError> {
        // Safety: btf_ext_header is POD so read_unaligned is safe
        let header = unsafe {
            ptr::read_unaligned::<btf_ext_header>(data.as_ptr() as *const btf_ext_header)
        };

        let rec_size = |offset, len| {
            let offset = mem::size_of::<btf_ext_header>() + offset as usize;
            let len = len as usize;
            // check that there's at least enough space for the `rec_size` field
            if (len > 0 && len < 4) || offset + len > data.len() {
                return Err(BtfError::InvalidInfo {
                    offset,
                    len,
                    section_len: data.len(),
                });
            }
            let read_u32 = if endianness == Endianness::Little {
                u32::from_le_bytes
            } else {
                u32::from_be_bytes
            };
            Ok(if len > 0 {
                read_u32(data[offset..offset + 4].try_into().unwrap()) as usize
            } else {
                0
            })
        };

        let btf_ext_header {
            func_info_off,
            func_info_len,
            line_info_off,
            line_info_len,
            core_relo_off,
            core_relo_len,
            ..
        } = header;

        let mut ext = BtfExt {
            header,
            relocations: Vec::new(),
            func_info: FuncInfo::new(),
            line_info: LineInfo::new(),
            func_info_rec_size: rec_size(func_info_off, func_info_len)?,
            line_info_rec_size: rec_size(line_info_off, line_info_len)?,
            core_relo_rec_size: rec_size(core_relo_off, core_relo_len)?,
            data: data.to_vec(),
            _endianness: endianness,
        };

        let func_info_rec_size = ext.func_info_rec_size;
        ext.func_info.data.extend(
            SecInfoIter::new(ext.func_info_data(), ext.func_info_rec_size, endianness)
                .map(move |sec| {
                    let name = btf
                        .string_at(sec.name_offset)
                        .ok()
                        .map(String::from)
                        .unwrap();
                    let info = FuncSecInfo::parse(
                        sec.name_offset,
                        sec.num_info,
                        func_info_rec_size,
                        sec.data,
                        endianness,
                    );
                    Ok((name, info))
                })
                .collect::<Result<HashMap<_, _>, _>>()?,
        );

        let line_info_rec_size = ext.line_info_rec_size;
        ext.line_info.data.extend(
            SecInfoIter::new(ext.line_info_data(), ext.line_info_rec_size, endianness)
                .map(move |sec| {
                    let name = btf
                        .string_at(sec.name_offset)
                        .ok()
                        .map(String::from)
                        .unwrap();
                    let info = LineSecInfo::parse(
                        sec.name_offset,
                        sec.num_info,
                        line_info_rec_size,
                        sec.data,
                        endianness,
                    );
                    Ok((name, info))
                })
                .collect::<Result<HashMap<_, _>, _>>()?,
        );

        let rec_size = ext.core_relo_rec_size;
        ext.relocations.extend(
            SecInfoIter::new(ext.core_relo_data(), ext.core_relo_rec_size, endianness)
                .map(move |sec| {
                    let relos = sec
                        .data
                        .chunks(rec_size)
                        .enumerate()
                        .map(|(n, rec)| unsafe { Relocation::parse(rec, n) })
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok((sec.name_offset, relos))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );

        Ok(ext)
    }

    fn info_data(&self, offset: u32, len: u32) -> &[u8] {
        let offset = (self.header.hdr_len + offset) as usize;
        let data = &self.data[offset..offset + len as usize];
        if len > 0 {
            // skip `rec_size`
            &data[4..]
        } else {
            data
        }
    }

    fn core_relo_data(&self) -> &[u8] {
        self.info_data(self.header.core_relo_off, self.header.core_relo_len)
    }

    fn func_info_data(&self) -> &[u8] {
        self.info_data(self.header.func_info_off, self.header.func_info_len)
    }

    fn line_info_data(&self) -> &[u8] {
        self.info_data(self.header.line_info_off, self.header.line_info_len)
    }

    pub(crate) fn relocations(&self) -> impl Iterator<Item = &(u32, Vec<Relocation>)> {
        self.relocations.iter()
    }

    pub(crate) fn func_info_rec_size(&self) -> usize {
        self.func_info_rec_size
    }

    pub(crate) fn line_info_rec_size(&self) -> usize {
        self.line_info_rec_size
    }
}

pub(crate) struct SecInfoIter<'a> {
    data: &'a [u8],
    offset: usize,
    rec_size: usize,
    endianness: Endianness,
}

impl<'a> SecInfoIter<'a> {
    fn new(data: &'a [u8], rec_size: usize, endianness: Endianness) -> Self {
        Self {
            data,
            rec_size,
            offset: 0,
            endianness,
        }
    }
}

impl<'a> Iterator for SecInfoIter<'a> {
    type Item = SecInfo<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let data = self.data;
        if self.offset + 8 >= data.len() {
            return None;
        }

        let read_u32 = if self.endianness == Endianness::Little {
            u32::from_le_bytes
        } else {
            u32::from_be_bytes
        };
        let name_offset = read_u32(data[self.offset..self.offset + 4].try_into().unwrap());
        self.offset += 4;
        let num_info = u32::from_ne_bytes(data[self.offset..self.offset + 4].try_into().unwrap());
        self.offset += 4;

        let data = &data[self.offset..self.offset + (self.rec_size * num_info as usize)];
        self.offset += self.rec_size * num_info as usize;

        Some(SecInfo {
            name_offset,
            num_info,
            data,
        })
    }
}

/// BtfTypes allows for access and manipulation of a
/// collection of BtfType objects
#[derive(Debug, Clone)]
pub(crate) struct BtfTypes {
    pub(crate) types: Vec<BtfType>,
}

impl Default for BtfTypes {
    fn default() -> Self {
        Self {
            types: vec![BtfType::Unknown],
        }
    }
}

impl BtfTypes {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        for t in self.types.iter().skip(1) {
            let b = t.to_bytes();
            buf.extend(b)
        }
        buf
    }

    pub(crate) fn len(&self) -> usize {
        self.types.len()
    }

    pub(crate) fn push(&mut self, value: BtfType) {
        self.types.push(value)
    }

    pub(crate) fn type_by_id(&self, type_id: u32) -> Result<&BtfType, BtfError> {
        self.types
            .get(type_id as usize)
            .ok_or(BtfError::UnknownBtfType { type_id })
    }

    pub(crate) fn resolve_type(&self, root_type_id: u32) -> Result<u32, BtfError> {
        let mut type_id = root_type_id;
        for _ in 0..MAX_RESOLVE_DEPTH {
            let ty = self.type_by_id(type_id)?;

            use BtfType::*;
            match ty {
                Volatile(ty) => {
                    type_id = ty.btf_type;
                    continue;
                }
                Const(ty) => {
                    type_id = ty.btf_type;
                    continue;
                }
                Restrict(ty) => {
                    type_id = ty.btf_type;
                    continue;
                }
                Typedef(ty) => {
                    type_id = ty.btf_type;
                    continue;
                }
                TypeTag(ty) => {
                    type_id = ty.btf_type;
                    continue;
                }
                _ => return Ok(type_id),
            }
        }

        Err(BtfError::MaximumTypeDepthReached {
            type_id: root_type_id,
        })
    }
}

#[derive(Debug)]
pub(crate) struct SecInfo<'a> {
    name_offset: u32,
    num_info: u32,
    data: &'a [u8],
}

#[cfg(test)]
mod tests {
    use crate::btf::{
        BtfParam, DataSec, DataSecEntry, DeclTag, Float, Func, FuncProto, Ptr, TypeTag, Var,
    };

    use super::*;

    #[test]
    fn test_parse_header() {
        let data: &[u8] = &[
            0x9f, 0xeb, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x54,
            0x2a, 0x00, 0x64, 0x54, 0x2a, 0x00, 0x10, 0x64, 0x1c, 0x00,
        ];
        let header = unsafe { read_btf_header(data) };
        assert_eq!(header.magic, 0xeb9f);
        assert_eq!(header.version, 0x01);
        assert_eq!(header.flags, 0x00);
        assert_eq!(header.hdr_len, 0x18);
        assert_eq!(header.type_off, 0x00);
        assert_eq!(header.type_len, 0x2a5464);
        assert_eq!(header.str_off, 0x2a5464);
        assert_eq!(header.str_len, 0x1c6410);
    }

    #[test]
    fn test_parse_btf() {
        // this generated BTF data is from an XDP program that simply returns XDP_PASS
        // compiled using clang
        let data: &[u8] = &[
            0x9f, 0xeb, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x01,
            0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00,
            0x00, 0x04, 0x18, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x20, 0x00,
            0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
            0x20, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x30, 0x00,
            0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x08, 0x04, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x0d, 0x06, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00,
            0x00, 0x01, 0x69, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0c, 0x05, 0x00, 0x00, 0x00,
            0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xbc, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
            0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x09, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0xd9, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00,
            0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x78,
            0x64, 0x70, 0x5f, 0x6d, 0x64, 0x00, 0x64, 0x61, 0x74, 0x61, 0x00, 0x64, 0x61, 0x74,
            0x61, 0x5f, 0x65, 0x6e, 0x64, 0x00, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x6d, 0x65, 0x74,
            0x61, 0x00, 0x69, 0x6e, 0x67, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x69, 0x66, 0x69, 0x6e,
            0x64, 0x65, 0x78, 0x00, 0x72, 0x78, 0x5f, 0x71, 0x75, 0x65, 0x75, 0x65, 0x5f, 0x69,
            0x6e, 0x64, 0x65, 0x78, 0x00, 0x65, 0x67, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x69, 0x66,
            0x69, 0x6e, 0x64, 0x65, 0x78, 0x00, 0x5f, 0x5f, 0x75, 0x33, 0x32, 0x00, 0x75, 0x6e,
            0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x74, 0x00, 0x63, 0x74, 0x78,
            0x00, 0x69, 0x6e, 0x74, 0x00, 0x78, 0x64, 0x70, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x00,
            0x78, 0x64, 0x70, 0x2f, 0x70, 0x61, 0x73, 0x73, 0x00, 0x2f, 0x68, 0x6f, 0x6d, 0x65,
            0x2f, 0x64, 0x61, 0x76, 0x65, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x62, 0x70, 0x66, 0x64,
            0x2f, 0x62, 0x70, 0x66, 0x2f, 0x78, 0x64, 0x70, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x2e,
            0x62, 0x70, 0x66, 0x2e, 0x63, 0x00, 0x20, 0x20, 0x20, 0x20, 0x72, 0x65, 0x74, 0x75,
            0x72, 0x6e, 0x20, 0x58, 0x44, 0x50, 0x5f, 0x50, 0x41, 0x53, 0x53, 0x3b, 0x00, 0x63,
            0x68, 0x61, 0x72, 0x00, 0x5f, 0x5f, 0x41, 0x52, 0x52, 0x41, 0x59, 0x5f, 0x53, 0x49,
            0x5a, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x5f, 0x00, 0x5f, 0x6c, 0x69, 0x63,
            0x65, 0x6e, 0x73, 0x65, 0x00, 0x6c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x00,
        ];
        assert_eq!(data.len(), 517);
        let got = Btf::parse(data, Endianness::default());
        match got {
            Ok(_) => {}
            Err(e) => panic!("{}", e),
        }
        let btf = got.unwrap();
        let data2 = btf.to_bytes();
        assert_eq!(data2.len(), 517);
        assert_eq!(data, data2);

        let ext_data: &[u8] = &[
            0x9f, 0xeb, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00,
            0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x72, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
            0x72, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b, 0x00,
            0x00, 0x00, 0xa2, 0x00, 0x00, 0x00, 0x05, 0x2c, 0x00, 0x00,
        ];

        assert_eq!(ext_data.len(), 80);
        let got = BtfExt::parse(ext_data, Endianness::default(), &btf);
        if let Err(e) = got {
            panic!("{}", e)
        }
    }

    #[test]
    fn test_write_btf() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("int".to_string());
        let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
        btf.add_type(int_type);

        let name_offset = btf.add_string("widget".to_string());
        let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
        btf.add_type(int_type);

        let btf_bytes = btf.to_bytes();
        let raw_btf = btf_bytes.as_slice();

        let parsed = Btf::parse(raw_btf, Endianness::default());
        match parsed {
            Ok(btf) => {
                assert_eq!(btf.string_at(1).unwrap(), "int");
                assert_eq!(btf.string_at(5).unwrap(), "widget");
            }
            Err(e) => {
                panic!("{}", e)
            }
        }
    }

    #[test]
    fn test_fixup_ptr() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("int".to_string());
        let int_type_id = btf.add_type(BtfType::Int(Int::new(
            name_offset,
            4,
            IntEncoding::Signed,
            0,
        )));

        let name_offset = btf.add_string("&mut int".to_string());
        let ptr_type_id = btf.add_type(BtfType::Ptr(Ptr::new(name_offset, int_type_id)));

        let features = Default::default();

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();
        if let BtfType::Ptr(fixed) = btf.type_by_id(ptr_type_id).unwrap() {
            assert!(
                fixed.name_offset == 0,
                "expected offset 0, got {}",
                fixed.name_offset
            )
        } else {
            panic!("not a ptr")
        }
        // Ensure we can convert to bytes and back again
        let raw = btf.to_bytes();
        Btf::parse(&raw, Endianness::default()).unwrap();
    }

    #[test]
    fn test_sanitize_var() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("int".to_string());
        let int_type_id = btf.add_type(BtfType::Int(Int::new(
            name_offset,
            4,
            IntEncoding::Signed,
            0,
        )));

        let name_offset = btf.add_string("&mut int".to_string());
        let var_type_id = btf.add_type(BtfType::Var(Var::new(
            name_offset,
            int_type_id,
            VarLinkage::Static,
        )));

        let features = BtfFeatures {
            btf_datasec: false,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();
        if let BtfType::Int(fixed) = btf.type_by_id(var_type_id).unwrap() {
            assert!(fixed.name_offset == name_offset)
        } else {
            panic!("not an int")
        }
        // Ensure we can convert to bytes and back again
        let raw = btf.to_bytes();
        Btf::parse(&raw, Endianness::default()).unwrap();
    }

    #[test]
    fn test_sanitize_datasec() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("int".to_string());
        let int_type_id = btf.add_type(BtfType::Int(Int::new(
            name_offset,
            4,
            IntEncoding::Signed,
            0,
        )));

        let name_offset = btf.add_string("foo".to_string());
        let var_type_id = btf.add_type(BtfType::Var(Var::new(
            name_offset,
            int_type_id,
            VarLinkage::Static,
        )));

        let name_offset = btf.add_string("data".to_string());
        let variables = vec![DataSecEntry {
            btf_type: var_type_id,
            offset: 0,
            size: 4,
        }];
        let datasec_type_id =
            btf.add_type(BtfType::DataSec(DataSec::new(name_offset, variables, 0)));

        let features = BtfFeatures {
            btf_datasec: false,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();
        if let BtfType::Struct(fixed) = btf.type_by_id(datasec_type_id).unwrap() {
            assert!(fixed.name_offset == name_offset);
            assert!(fixed.members.len() == 1);
            assert!(fixed.members[0].btf_type == var_type_id);
            assert!(fixed.members[0].offset == 0)
        } else {
            panic!("not a struct")
        }
        // Ensure we can convert to bytes and back again
        let raw = btf.to_bytes();
        Btf::parse(&raw, Endianness::default()).unwrap();
    }

    #[test]
    fn test_fixup_datasec() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("int".to_string());
        let int_type_id = btf.add_type(BtfType::Int(Int::new(
            name_offset,
            4,
            IntEncoding::Signed,
            0,
        )));

        let name_offset = btf.add_string("foo".to_string());
        let var_type_id = btf.add_type(BtfType::Var(Var::new(
            name_offset,
            int_type_id,
            VarLinkage::Global,
        )));

        let name_offset = btf.add_string(".data/foo".to_string());
        let variables = vec![DataSecEntry {
            btf_type: var_type_id,
            offset: 0,
            size: 4,
        }];
        let datasec_type_id =
            btf.add_type(BtfType::DataSec(DataSec::new(name_offset, variables, 0)));

        let features = BtfFeatures {
            btf_datasec: true,
            ..Default::default()
        };

        btf.fixup_and_sanitize(
            &HashMap::from([(".data/foo".to_string(), 32u64)]),
            &HashMap::from([("foo".to_string(), 64u64)]),
            &features,
        )
        .unwrap();

        if let BtfType::DataSec(fixed) = btf.type_by_id(datasec_type_id).unwrap() {
            assert!(fixed.name_offset != name_offset);
            assert!(fixed.size == 32);
            assert!(fixed.entries.len() == 1);
            assert!(fixed.entries[0].btf_type == var_type_id);
            assert!(
                fixed.entries[0].offset == 64,
                "expected 64, got {}",
                fixed.entries[0].offset
            );
            assert!(btf.string_at(fixed.name_offset).unwrap() == ".data.foo")
        } else {
            panic!("not a datasec")
        }
        // Ensure we can convert to bytes and back again
        let raw = btf.to_bytes();
        Btf::parse(&raw, Endianness::default()).unwrap();
    }

    #[test]
    fn test_sanitize_func_and_proto() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("int".to_string());
        let int_type_id = btf.add_type(BtfType::Int(Int::new(
            name_offset,
            4,
            IntEncoding::Signed,
            0,
        )));

        let params = vec![
            BtfParam {
                name_offset: btf.add_string("a".to_string()),
                btf_type: int_type_id,
            },
            BtfParam {
                name_offset: btf.add_string("b".to_string()),
                btf_type: int_type_id,
            },
        ];
        let func_proto_type_id =
            btf.add_type(BtfType::FuncProto(FuncProto::new(params, int_type_id)));
        let inc = btf.add_string("inc".to_string());
        let func_type_id = btf.add_type(BtfType::Func(Func::new(
            inc,
            func_proto_type_id,
            FuncLinkage::Static,
        )));

        let features = BtfFeatures {
            btf_func: false,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();
        if let BtfType::Enum(fixed) = btf.type_by_id(func_proto_type_id).unwrap() {
            assert!(fixed.name_offset == 0);
            assert!(fixed.variants.len() == 2);
            assert!(btf.string_at(fixed.variants[0].name_offset).unwrap() == "a");
            assert!(fixed.variants[0].value == int_type_id);
            assert!(btf.string_at(fixed.variants[1].name_offset).unwrap() == "b");
            assert!(fixed.variants[1].value == int_type_id);
        } else {
            panic!("not an emum")
        }

        if let BtfType::Typedef(fixed) = btf.type_by_id(func_type_id).unwrap() {
            assert!(fixed.name_offset == inc);
            assert!(fixed.btf_type == func_proto_type_id);
        } else {
            panic!("not a typedef")
        }
        // Ensure we can convert to bytes and back again
        let raw = btf.to_bytes();
        Btf::parse(&raw, Endianness::default()).unwrap();
    }

    #[test]
    fn test_fixup_func_proto() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("int".to_string());
        let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
        let int_type_id = btf.add_type(int_type);

        let params = vec![
            BtfParam {
                name_offset: 0,
                btf_type: int_type_id,
            },
            BtfParam {
                name_offset: 0,
                btf_type: int_type_id,
            },
        ];
        let func_proto = BtfType::FuncProto(FuncProto::new(params, int_type_id));
        let func_proto_type_id = btf.add_type(func_proto);

        let features = BtfFeatures {
            btf_func: true,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();

        if let BtfType::FuncProto(fixed) = btf.type_by_id(func_proto_type_id).unwrap() {
            assert!(btf.string_at(fixed.params[0].name_offset).unwrap() == "param0");
            assert!(btf.string_at(fixed.params[1].name_offset).unwrap() == "param1");
        } else {
            panic!("not a func_proto")
        }
        // Ensure we can convert to bytes and back again
        let raw = btf.to_bytes();
        Btf::parse(&raw, Endianness::default()).unwrap();
    }

    #[test]
    fn test_sanitize_func_global() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("int".to_string());
        let int_type_id = btf.add_type(BtfType::Int(Int::new(
            name_offset,
            4,
            IntEncoding::Signed,
            0,
        )));

        let params = vec![
            BtfParam {
                name_offset: btf.add_string("a".to_string()),
                btf_type: int_type_id,
            },
            BtfParam {
                name_offset: btf.add_string("b".to_string()),
                btf_type: int_type_id,
            },
        ];
        let func_proto_type_id =
            btf.add_type(BtfType::FuncProto(FuncProto::new(params, int_type_id)));
        let inc = btf.add_string("inc".to_string());
        let func_type_id = btf.add_type(BtfType::Func(Func::new(
            inc,
            func_proto_type_id,
            FuncLinkage::Global,
        )));

        let features = BtfFeatures {
            btf_func: true,
            btf_func_global: false,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();

        if let BtfType::Func(fixed) = btf.type_by_id(func_type_id).unwrap() {
            assert!(fixed.linkage() == FuncLinkage::Static);
        } else {
            panic!("not a func")
        }
        // Ensure we can convert to bytes and back again
        let raw = btf.to_bytes();
        Btf::parse(&raw, Endianness::default()).unwrap();
    }

    #[test]
    fn test_sanitize_mem_builtins() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("int".to_string());
        let int_type_id = btf.add_type(BtfType::Int(Int::new(
            name_offset,
            4,
            IntEncoding::Signed,
            0,
        )));

        let params = vec![
            BtfParam {
                name_offset: btf.add_string("a".to_string()),
                btf_type: int_type_id,
            },
            BtfParam {
                name_offset: btf.add_string("b".to_string()),
                btf_type: int_type_id,
            },
        ];
        let func_proto_type_id =
            btf.add_type(BtfType::FuncProto(FuncProto::new(params, int_type_id)));

        let builtins = ["memset", "memcpy", "memcmp", "memmove"];
        for fname in builtins {
            let func_name_offset = btf.add_string(fname.to_string());
            let func_type_id = btf.add_type(BtfType::Func(Func::new(
                func_name_offset,
                func_proto_type_id,
                FuncLinkage::Global,
            )));

            let features = BtfFeatures {
                btf_func: true,
                btf_func_global: true, // to force function name check
                ..Default::default()
            };

            btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
                .unwrap();

            if let BtfType::Func(fixed) = btf.type_by_id(func_type_id).unwrap() {
                assert!(fixed.linkage() == FuncLinkage::Static);
            } else {
                panic!("not a func")
            }

            // Ensure we can convert to bytes and back again
            let raw = btf.to_bytes();
            Btf::parse(&raw, Endianness::default()).unwrap();
        }
    }

    #[test]
    fn test_sanitize_float() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("float".to_string());
        let float_type_id = btf.add_type(BtfType::Float(Float::new(name_offset, 16)));

        let features = BtfFeatures {
            btf_float: false,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();
        if let BtfType::Struct(fixed) = btf.type_by_id(float_type_id).unwrap() {
            assert!(fixed.name_offset == 0);
            assert!(fixed.size == 16);
        } else {
            panic!("not a struct")
        }
        // Ensure we can convert to bytes and back again
        let raw = btf.to_bytes();
        Btf::parse(&raw, Endianness::default()).unwrap();
    }

    #[test]
    fn test_sanitize_decl_tag() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("int".to_string());
        let int_type_id = btf.add_type(BtfType::Int(Int::new(
            name_offset,
            4,
            IntEncoding::Signed,
            0,
        )));

        let name_offset = btf.add_string("foo".to_string());
        let var_type_id = btf.add_type(BtfType::Var(Var::new(
            name_offset,
            int_type_id,
            VarLinkage::Static,
        )));

        let name_offset = btf.add_string("decl_tag".to_string());
        let decl_tag_type_id =
            btf.add_type(BtfType::DeclTag(DeclTag::new(name_offset, var_type_id, -1)));

        let features = BtfFeatures {
            btf_decl_tag: false,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();
        if let BtfType::Int(fixed) = btf.type_by_id(decl_tag_type_id).unwrap() {
            assert!(fixed.name_offset == name_offset);
            assert!(fixed.size == 1);
        } else {
            panic!("not an int")
        }
        // Ensure we can convert to bytes and back again
        let raw = btf.to_bytes();
        Btf::parse(&raw, Endianness::default()).unwrap();
    }

    #[test]
    fn test_sanitize_type_tag() {
        let mut btf = Btf::new();

        let int_type_id = btf.add_type(BtfType::Int(Int::new(0, 4, IntEncoding::Signed, 0)));

        let name_offset = btf.add_string("int".to_string());
        let type_tag_type = btf.add_type(BtfType::TypeTag(TypeTag::new(name_offset, int_type_id)));
        btf.add_type(BtfType::Ptr(Ptr::new(0, type_tag_type)));

        let features = BtfFeatures {
            btf_type_tag: false,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();
        if let BtfType::Const(fixed) = btf.type_by_id(type_tag_type).unwrap() {
            assert!(fixed.btf_type == int_type_id);
        } else {
            panic!("not a const")
        }
        // Ensure we can convert to bytes and back again
        let raw = btf.to_bytes();
        Btf::parse(&raw, Endianness::default()).unwrap();
    }

    #[test]
    #[cfg(feature = "std")]
    #[cfg_attr(miri, ignore)]
    fn test_read_btf_from_sys_fs() {
        let btf = Btf::parse_file("/sys/kernel/btf/vmlinux", Endianness::default()).unwrap();
        let task_struct_id = btf
            .id_by_type_name_kind("task_struct", BtfKind::Struct)
            .unwrap();
        // we can't assert on exact ID since this may change across kernel versions
        assert!(task_struct_id != 0);

        let netif_id = btf
            .id_by_type_name_kind("netif_receive_skb", BtfKind::Func)
            .unwrap();
        assert!(netif_id != 0);

        let u32_def = btf.id_by_type_name_kind("__u32", BtfKind::Typedef).unwrap();
        assert!(u32_def != 0);

        let u32_base = btf.resolve_type(u32_def).unwrap();
        assert!(u32_base != 0);

        let u32_ty = btf.type_by_id(u32_base).unwrap();
        assert_eq!(u32_ty.kind(), BtfKind::Int);
    }
}
