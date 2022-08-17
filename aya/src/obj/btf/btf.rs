use std::{
    borrow::Cow,
    collections::HashMap,
    ffi::{c_void, CStr, CString},
    fs, io, mem,
    path::{Path, PathBuf},
    ptr,
};

use bytes::BufMut;

use log::debug;
use object::Endianness;
use thiserror::Error;

use crate::{
    generated::{btf_enum, btf_ext_header, btf_func_linkage, btf_header, btf_member},
    obj::btf::{relocation::Relocation, BtfKind, BtfType},
    util::bytes_of,
    Features,
};

use super::{
    info::{FuncSecInfo, LineSecInfo},
    type_vlen, FuncInfo, LineInfo,
};

pub(crate) const MAX_RESOLVE_DEPTH: u8 = 32;
pub(crate) const MAX_SPEC_LEN: usize = 64;

/// The error type returned when `BTF` operations fail.
#[derive(Error, Debug)]
pub enum BtfError {
    /// Error parsing file
    #[error("error parsing {path}")]
    FileError {
        /// file path
        path: PathBuf,
        /// source of the error
        #[source]
        error: io::Error,
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

    /// Loading the btf failed
    #[error("the BPF_BTF_LOAD syscall failed. Verifier output: {verifier_log}")]
    LoadError {
        /// The [`io::Error`] returned by the `BPF_BTF_LOAD` syscall.
        #[source]
        io_error: io::Error,
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

/// Bpf Type Format metadata.
///
/// BTF is a kind of debug metadata that allows eBPF programs compiled against one kernel version
/// to be loaded into different kernel versions.
///
/// Aya automatically loads BTF metadata if you use [`Bpf::load_file`](crate::Bpf::load_file). You
/// only need to explicitly use this type if you want to load BTF from a non-standard
/// location or if you are using [`Bpf::load`](crate::Bpf::load).
#[derive(Clone, Debug)]
pub struct Btf {
    header: btf_header,
    strings: Vec<u8>,
    types: BtfTypes,
    _endianness: Endianness,
}

impl Btf {
    pub(crate) fn new() -> Btf {
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

    pub(crate) fn add_string(&mut self, name: String) -> u32 {
        let str = CString::new(name).unwrap();
        let name_off = self.strings.len();
        self.strings.extend(str.as_c_str().to_bytes_with_nul());
        self.header.str_len = self.strings.len() as u32;
        name_off as u32
    }

    pub(crate) fn add_type(&mut self, type_: BtfType) -> u32 {
        let size = type_.type_info_size() as u32;
        let type_id = self.types.len();
        self.types.push(type_);
        self.header.type_len += size;
        self.header.str_off += size;
        type_id as u32
    }

    /// Loads BTF metadata from `/sys/kernel/btf/vmlinux`.
    pub fn from_sys_fs() -> Result<Btf, BtfError> {
        Btf::parse_file("/sys/kernel/btf/vmlinux", Endianness::default())
    }

    /// Loads BTF metadata from the given `path`.
    pub fn parse_file<P: AsRef<Path>>(path: P, endianness: Endianness) -> Result<Btf, BtfError> {
        let path = path.as_ref();
        Btf::parse(
            &fs::read(path).map_err(|error| BtfError::FileError {
                path: path.to_owned(),
                error,
            })?,
            endianness,
        )
    }

    pub(crate) fn parse(data: &[u8], endianness: Endianness) -> Result<Btf, BtfError> {
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

    pub(crate) fn type_name(&self, ty: &BtfType) -> Result<Option<Cow<'_, str>>, BtfError> {
        ty.name_offset().map(|off| self.string_at(off)).transpose()
    }

    pub(crate) fn err_type_name(&self, ty: &BtfType) -> Option<String> {
        ty.name_offset()
            .and_then(|off| self.string_at(off).ok().map(String::from))
    }

    pub(crate) fn id_by_type_name_kind(&self, name: &str, kind: BtfKind) -> Result<u32, BtfError> {
        for (type_id, ty) in self.types().enumerate() {
            match ty.kind()? {
                Some(k) => {
                    if k != kind {
                        continue;
                    }
                }
                None => continue,
            }

            match self.type_name(ty)? {
                Some(ty_name) => {
                    if ty_name == name {
                        return Ok(type_id as u32);
                    }
                    continue;
                }
                None => continue,
            }
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

            use BtfType::*;
            let size = match ty {
                Int(ty, _)
                | Struct(ty, _)
                | Union(ty, _)
                | Enum(ty, _)
                | DataSec(ty, _)
                | Float(ty) => {
                    // Safety: union
                    unsafe { ty.__bindgen_anon_1.size as usize }
                }
                Ptr(_) => mem::size_of::<*const c_void>(), // FIXME
                Typedef(ty)
                | Volatile(ty)
                | Const(ty)
                | Restrict(ty)
                | Var(ty, _)
                | DeclTag(ty, _)
                | TypeTag(ty) => {
                    // Safety: union
                    type_id = unsafe { ty.__bindgen_anon_1.type_ };
                    continue;
                }
                Array(_, array) => {
                    n_elems *= array.nelems as usize;
                    type_id = array.type_;
                    continue;
                }
                Unknown | Fwd(_) | Func(_) | FuncProto(_, _) => {
                    return Err(BtfError::UnexpectedBtfType { type_id })
                }
            };

            return Ok(size * n_elems);
        }

        Err(BtfError::MaximumTypeDepthReached {
            type_id: root_type_id,
        })
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
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
        features: &Features,
    ) -> Result<(), BtfError> {
        let mut types = mem::take(&mut self.types);
        for i in 0..types.types.len() {
            let t = &types.types[i];
            let kind = t.kind()?.unwrap_or_default();
            match t {
                // Fixup PTR for Rust
                // LLVM emits names for Rust pointer types, which the kernel doesn't like
                // While I figure out if this needs fixing in the Kernel or LLVM, we'll
                // do a fixup here
                BtfType::Ptr(ty) => {
                    let mut fixed_ty = *ty;
                    fixed_ty.name_off = 0;
                    types.types[i] = BtfType::Ptr(fixed_ty)
                }
                // Sanitize VAR if they are not supported
                BtfType::Var(ty, _) if !features.btf_datasec => {
                    types.types[i] = BtfType::new_int(ty.name_off, 1, 0, 0);
                }
                // Sanitize DATASEC if they are not supported
                BtfType::DataSec(ty, data) if !features.btf_datasec => {
                    debug!("{}: not supported. replacing with STRUCT", kind);
                    let mut members = vec![];
                    for member in data {
                        let mt = types.type_by_id(member.type_).unwrap();
                        members.push(btf_member {
                            name_off: mt.btf_type().unwrap().name_off,
                            type_: member.type_,
                            offset: member.offset * 8,
                        })
                    }
                    types.types[i] = BtfType::new_struct(ty.name_off, members, 0);
                }
                // Fixup DATASEC
                // DATASEC sizes aren't always set by LLVM
                // we need to fix them here before loading the btf to the kernel
                BtfType::DataSec(ty, data) if features.btf_datasec => {
                    // Start DataSec Fixups
                    let sec_name = self.string_at(ty.name_off)?;
                    let name = sec_name.to_string();

                    let mut fixed_ty = *ty;
                    let mut fixed_data = data.clone();

                    // Handle any "/" characters in section names
                    // Example: "maps/hashmap"
                    let fixed_name = name.replace('/', ".");
                    if fixed_name != name {
                        fixed_ty.name_off = self.add_string(fixed_name);
                    }

                    // There are some cases when the compiler does indeed populate the
                    // size
                    if unsafe { ty.__bindgen_anon_1.size > 0 } {
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
                        fixed_ty.__bindgen_anon_1.size = *size as u32;

                        // The Vec<btf_var_secinfo> contains BTF_KIND_VAR sections
                        // that need to have their offsets adjusted. To do this,
                        // we need to get the offset from the ELF file.
                        // This was also cached during initial parsing and
                        // we can query by name in symbol_offsets
                        for d in &mut fixed_data {
                            let var_type = types.type_by_id(d.type_)?;
                            let var_kind = var_type.kind()?.unwrap();
                            if let BtfType::Var(vty, var) = var_type {
                                let var_name = self.string_at(vty.name_off)?.to_string();
                                if var.linkage == btf_func_linkage::BTF_FUNC_STATIC as u32 {
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
                    types.types[i] = BtfType::DataSec(fixed_ty, fixed_data);
                }
                // Fixup FUNC_PROTO
                BtfType::FuncProto(ty, params) if features.btf_func => {
                    let mut params = params.clone();
                    for (i, mut param) in params.iter_mut().enumerate() {
                        if param.name_off == 0 && param.type_ != 0 {
                            param.name_off = self.add_string(format!("param{}", i));
                        }
                    }
                    types.types[i] = BtfType::FuncProto(*ty, params);
                }
                // Sanitize FUNC_PROTO
                BtfType::FuncProto(ty, vars) if !features.btf_func => {
                    debug!("{}: not supported. replacing with ENUM", kind);
                    let members: Vec<btf_enum> = vars
                        .iter()
                        .map(|p| btf_enum {
                            name_off: p.name_off,
                            val: p.type_ as i32,
                        })
                        .collect();
                    let enum_type = BtfType::new_enum(ty.name_off, members);
                    types.types[i] = enum_type;
                }
                // Sanitize FUNC
                BtfType::Func(ty) if !features.btf_func => {
                    debug!("{}: not supported. replacing with TYPEDEF", kind);
                    let typedef_type =
                        BtfType::new_typedef(ty.name_off, unsafe { ty.__bindgen_anon_1.type_ });
                    types.types[i] = typedef_type;
                }
                // Sanitize BTF_FUNC_GLOBAL
                BtfType::Func(ty) if !features.btf_func_global => {
                    let mut fixed_ty = *ty;
                    if type_vlen(ty) == btf_func_linkage::BTF_FUNC_GLOBAL as usize {
                        debug!(
                            "{}: BTF_FUNC_GLOBAL not supported. replacing with BTF_FUNC_STATIC",
                            kind
                        );
                        fixed_ty.info = (ty.info & 0xFFFF0000)
                            | (btf_func_linkage::BTF_FUNC_STATIC as u32) & 0xFFFF;
                    }
                    types.types[i] = BtfType::Func(fixed_ty);
                }
                // Sanitize FLOAT
                BtfType::Float(ty) if !features.btf_float => {
                    debug!("{}: not supported. replacing with STRUCT", kind);
                    let struct_ty =
                        BtfType::new_struct(0, vec![], unsafe { ty.__bindgen_anon_1.size });
                    types.types[i] = struct_ty;
                }
                // Sanitize DECL_TAG
                BtfType::DeclTag(ty, _) if !features.btf_decl_tag => {
                    debug!("{}: not supported. replacing with INT", kind);
                    let int_type = BtfType::new_int(ty.name_off, 1, 0, 0);
                    types.types[i] = int_type;
                }
                // Sanitize TYPE_TAG
                BtfType::TypeTag(ty) if !features.btf_type_tag => {
                    debug!("{}: not supported. replacing with CONST", kind);
                    let const_type = BtfType::new_const(unsafe { ty.__bindgen_anon_1.type_ });
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

unsafe fn read_btf_header(data: &[u8]) -> btf_header {
    // safety: btf_header is POD so read_unaligned is safe
    ptr::read_unaligned(data.as_ptr() as *const btf_header)
}

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
                        .string_at(sec.sec_name_off)
                        .ok()
                        .map(String::from)
                        .unwrap();
                    let info = FuncSecInfo::parse(
                        sec.sec_name_off,
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
                        .string_at(sec.sec_name_off)
                        .ok()
                        .map(String::from)
                        .unwrap();
                    let info = LineSecInfo::parse(
                        sec.sec_name_off,
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
                    Ok((sec.sec_name_off, relos))
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
        let sec_name_off = read_u32(data[self.offset..self.offset + 4].try_into().unwrap());
        self.offset += 4;
        let num_info = u32::from_ne_bytes(data[self.offset..self.offset + 4].try_into().unwrap());
        self.offset += 4;

        let data = &data[self.offset..self.offset + (self.rec_size * num_info as usize)];
        self.offset += self.rec_size * num_info as usize;

        Some(SecInfo {
            sec_name_off,
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
            buf.put(b.as_slice())
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
                Volatile(ty) | Const(ty) | Restrict(ty) | Typedef(ty) | TypeTag(ty) => {
                    // Safety: union
                    type_id = unsafe { ty.__bindgen_anon_1.type_ };
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
    sec_name_off: u32,
    num_info: u32,
    data: &'a [u8],
}

#[cfg(test)]
mod tests {
    use crate::generated::{
        btf_param, btf_var_secinfo, BTF_INT_SIGNED, BTF_VAR_GLOBAL_EXTERN, BTF_VAR_STATIC,
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
        let int_type = BtfType::new_int(name_offset, 4, BTF_INT_SIGNED, 0);
        btf.add_type(int_type);

        let name_offset = btf.add_string("widget".to_string());
        let int_type = BtfType::new_int(name_offset, 4, BTF_INT_SIGNED, 0);
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
        let int_type_id = btf.add_type(BtfType::new_int(name_offset, 4, BTF_INT_SIGNED, 0));

        let name_offset = btf.add_string("&mut int".to_string());
        let ptr_type_id = btf.add_type(BtfType::new_ptr(name_offset, int_type_id));

        let features = Features {
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();
        if let BtfType::Ptr(fixed) = btf.type_by_id(ptr_type_id).unwrap() {
            assert!(
                fixed.name_off == 0,
                "expected offset 0, got {}",
                fixed.name_off
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
        let int_type_id = btf.add_type(BtfType::new_int(name_offset, 4, BTF_INT_SIGNED, 0));

        let name_offset = btf.add_string("&mut int".to_string());
        let var_type_id = btf.add_type(BtfType::new_var(name_offset, int_type_id, BTF_VAR_STATIC));

        let features = Features {
            btf_datasec: false,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();
        if let BtfType::Int(fixed, _) = btf.type_by_id(var_type_id).unwrap() {
            assert!(fixed.name_off == name_offset)
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
        let int_type_id = btf.add_type(BtfType::new_int(name_offset, 4, BTF_INT_SIGNED, 0));

        let name_offset = btf.add_string("foo".to_string());
        let var_type_id = btf.add_type(BtfType::new_var(name_offset, int_type_id, BTF_VAR_STATIC));

        let name_offset = btf.add_string(".data".to_string());
        let variables = vec![btf_var_secinfo {
            type_: var_type_id,
            offset: 0,
            size: 4,
        }];
        let datasec_type_id = btf.add_type(BtfType::new_datasec(name_offset, variables, 0));

        let features = Features {
            btf_datasec: false,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();
        if let BtfType::Struct(fixed, members) = btf.type_by_id(datasec_type_id).unwrap() {
            assert!(fixed.name_off == name_offset);
            assert!(members.len() == 1);
            assert!(members[0].type_ == var_type_id);
            assert!(members[0].offset == 0)
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
        let int_type_id = btf.add_type(BtfType::new_int(name_offset, 4, BTF_INT_SIGNED, 0));

        let name_offset = btf.add_string("foo".to_string());
        let var_type_id = btf.add_type(BtfType::new_var(
            name_offset,
            int_type_id,
            BTF_VAR_GLOBAL_EXTERN,
        ));

        let name_offset = btf.add_string(".data/foo".to_string());
        let variables = vec![btf_var_secinfo {
            type_: var_type_id,
            offset: 0,
            size: 4,
        }];
        let datasec_type_id = btf.add_type(BtfType::new_datasec(name_offset, variables, 0));

        let features = Features {
            btf_datasec: true,
            ..Default::default()
        };

        btf.fixup_and_sanitize(
            &HashMap::from([(".data/foo".to_string(), 32u64)]),
            &HashMap::from([("foo".to_string(), 64u64)]),
            &features,
        )
        .unwrap();

        if let BtfType::DataSec(fixed, sec_info) = btf.type_by_id(datasec_type_id).unwrap() {
            assert!(fixed.name_off != name_offset);
            assert!(unsafe { fixed.__bindgen_anon_1.size } == 32);
            assert!(sec_info.len() == 1);
            assert!(sec_info[0].type_ == var_type_id);
            assert!(
                sec_info[0].offset == 64,
                "expected 64, got {}",
                sec_info[0].offset
            );
            assert!(btf.string_at(fixed.name_off).unwrap() == ".data.foo")
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
        let int_type_id = btf.add_type(BtfType::new_int(name_offset, 4, BTF_INT_SIGNED, 0));

        let params = vec![
            btf_param {
                name_off: btf.add_string("a".to_string()),
                type_: int_type_id,
            },
            btf_param {
                name_off: btf.add_string("b".to_string()),
                type_: int_type_id,
            },
        ];
        let func_proto_type_id = btf.add_type(BtfType::new_func_proto(params, int_type_id));
        let inc = btf.add_string("inc".to_string());
        let func_type_id = btf.add_type(BtfType::new_func(
            inc,
            func_proto_type_id,
            btf_func_linkage::BTF_FUNC_STATIC,
        ));

        let features = Features {
            btf_func: false,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();

        if let BtfType::Enum(fixed, vars) = btf.type_by_id(func_proto_type_id).unwrap() {
            assert!(fixed.name_off == 0);
            assert!(vars.len() == 2);
            assert!(btf.string_at(vars[0].name_off).unwrap() == "a");
            assert!(vars[0].val == int_type_id as i32);
            assert!(btf.string_at(vars[1].name_off).unwrap() == "b");
            assert!(vars[1].val == int_type_id as i32);
        } else {
            panic!("not an emum")
        }

        if let BtfType::Typedef(fixed) = btf.type_by_id(func_type_id).unwrap() {
            assert!(fixed.name_off == inc);
            assert!(unsafe { fixed.__bindgen_anon_1.type_ } == func_proto_type_id);
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
        let int_type = BtfType::new_int(name_offset, 4, BTF_INT_SIGNED, 0);
        let int_type_id = btf.add_type(int_type);

        let params = vec![
            btf_param {
                name_off: 0,
                type_: int_type_id,
            },
            btf_param {
                name_off: 0,
                type_: int_type_id,
            },
        ];
        let func_proto = BtfType::new_func_proto(params, int_type_id);
        let func_proto_type_id = btf.add_type(func_proto);

        let features = Features {
            btf_func: true,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();

        if let BtfType::FuncProto(_, vars) = btf.type_by_id(func_proto_type_id).unwrap() {
            assert!(btf.string_at(vars[0].name_off).unwrap() == "param0");
            assert!(btf.string_at(vars[1].name_off).unwrap() == "param1");
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
        let int_type_id = btf.add_type(BtfType::new_int(name_offset, 4, BTF_INT_SIGNED, 0));

        let params = vec![
            btf_param {
                name_off: btf.add_string("a".to_string()),
                type_: int_type_id,
            },
            btf_param {
                name_off: btf.add_string("b".to_string()),
                type_: int_type_id,
            },
        ];
        let func_proto_type_id = btf.add_type(BtfType::new_func_proto(params, int_type_id));
        let inc = btf.add_string("inc".to_string());
        let func_type_id = btf.add_type(BtfType::new_func(
            inc,
            func_proto_type_id,
            btf_func_linkage::BTF_FUNC_GLOBAL,
        ));

        let features = Features {
            btf_func: true,
            btf_func_global: false,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();

        if let BtfType::Func(fixed) = btf.type_by_id(func_type_id).unwrap() {
            assert!(type_vlen(fixed) == btf_func_linkage::BTF_FUNC_STATIC as usize);
        } else {
            panic!("not a func")
        }
        // Ensure we can convert to bytes and back again
        let raw = btf.to_bytes();
        Btf::parse(&raw, Endianness::default()).unwrap();
    }

    #[test]
    fn test_sanitize_float() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("float".to_string());
        let float_type_id = btf.add_type(BtfType::new_float(name_offset, 16));

        let features = Features {
            btf_float: false,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();
        if let BtfType::Struct(fixed, _) = btf.type_by_id(float_type_id).unwrap() {
            assert!(fixed.name_off == 0);
            assert!(unsafe { fixed.__bindgen_anon_1.size } == 16);
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
        let int_type_id = btf.add_type(BtfType::new_int(name_offset, 4, BTF_INT_SIGNED, 0));

        let name_offset = btf.add_string("foo".to_string());
        let var_type_id = btf.add_type(BtfType::new_var(name_offset, int_type_id, BTF_VAR_STATIC));

        let name_offset = btf.add_string("decl_tag".to_string());
        let decl_tag_type_id = btf.add_type(BtfType::new_decl_tag(name_offset, var_type_id, -1));

        let features = Features {
            btf_decl_tag: false,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();
        if let BtfType::Int(fixed, _) = btf.type_by_id(decl_tag_type_id).unwrap() {
            assert!(fixed.name_off == name_offset);
            assert!(unsafe { fixed.__bindgen_anon_1.size } == 1);
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

        let int_type_id = btf.add_type(BtfType::new_int(0, 4, BTF_INT_SIGNED, 0));

        let name_offset = btf.add_string("int".to_string());
        let type_tag_type = btf.add_type(BtfType::new_type_tag(name_offset, int_type_id));
        btf.add_type(BtfType::new_ptr(0, type_tag_type));

        let features = Features {
            btf_type_tag: false,
            ..Default::default()
        };

        btf.fixup_and_sanitize(&HashMap::new(), &HashMap::new(), &features)
            .unwrap();
        if let BtfType::Const(fixed) = btf.type_by_id(type_tag_type).unwrap() {
            assert!(unsafe { fixed.__bindgen_anon_1.type_ } == int_type_id);
        } else {
            panic!("not a const")
        }
        // Ensure we can convert to bytes and back again
        let raw = btf.to_bytes();
        Btf::parse(&raw, Endianness::default()).unwrap();
    }
}
