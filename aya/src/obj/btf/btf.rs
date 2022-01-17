use std::{
    borrow::Cow,
    collections::HashMap,
    convert::TryInto,
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
    types: Vec<BtfType>,
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
            types: vec![BtfType::Unknown],
            _endianness: Endianness::default(),
        }
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
    ) -> Result<Vec<BtfType>, BtfError> {
        let hdr_len = header.hdr_len as usize;
        let type_off = header.type_off as usize;
        let type_len = header.type_len as usize;
        let base = hdr_len + type_off;
        if base + type_len > data.len() {
            return Err(BtfError::InvalidTypeInfo);
        }

        let mut data = &data[base..base + type_len];
        let mut types = vec![BtfType::Unknown];
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
        self.types
            .get(type_id as usize)
            .ok_or(BtfError::UnknownBtfType { type_id })
    }

    pub(crate) fn types(&self) -> impl Iterator<Item = &BtfType> {
        self.types.iter()
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
            let ty = self.type_by_id(type_id)?;

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
        for t in self.types().skip(1) {
            let b = t.to_bytes();
            buf.put(b.as_slice())
        }
        buf.put(self.strings.as_slice());
        buf
    }

    pub(crate) fn fixup(
        &mut self,
        section_sizes: &HashMap<String, u64>,
        symbol_offsets: &HashMap<String, u64>,
    ) -> Result<(), BtfError> {
        let mut types = self.types.split_off(0);
        for t in &mut types {
            let kind = t.kind()?.unwrap_or_default();
            // datasec sizes aren't set by llvm
            // we need to fix them here before loading the btf to the kernel
            match t {
                BtfType::Ptr(mut ty) => {
                    // Rust emits names for pointer types, which the kernel doesn't like
                    // While I figure out if this needs fixing in the Kernel or LLVM, we'll
                    // do a fixup here
                    ty.name_off = 0;
                }
                BtfType::DataSec(mut ty, data) => {
                    // Start DataSec Fixups
                    let sec_name = self.string_at(ty.name_off)?;
                    let name = sec_name.to_string();
                    // There are cases when the compiler does indeed populate the
                    // size. If we hit this case, push to the types vector and
                    // continue
                    if unsafe { ty.__bindgen_anon_1.size > 0 } {
                        debug!("{} {}: fixup not required", kind, name);
                        continue;
                    }

                    // We need to get the size of the section from the ELF file
                    // Fortunately, we cached these when parsing it initially
                    // and we can this up by name in section_sizes
                    if let Some(size) = section_sizes.get(&name) {
                        debug!("{} {}: fixup size to {}", kind, name, size);
                        ty.__bindgen_anon_1.size = *size as u32;
                    } else {
                        return Err(BtfError::UnknownSectionSize { section_name: name });
                    }

                    // The Vec<btf_var_secinfo> contains BTF_KIND_VAR sections
                    // that need to have their offsets adjusted. To do this,
                    // we need to get the offset from the ELF file.
                    // This was also cached during initial parsing and
                    // we can query by name in symbol_offsets
                    for d in data {
                        let var_type = self.type_by_id(d.type_)?;
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
                BtfType::FuncProto(_ty, params) => {
                    for (i, mut param) in params.iter_mut().enumerate() {
                        if param.name_off == 0 && param.type_ != 0 {
                            param.name_off = self.add_string(format!("param{}", i));
                        }
                    }
                }
                // The type does not need fixing up
                _ => {}
            }
        }
        self.types = types;
        Ok(())
    }

    pub(crate) fn sanitize(&self, features: &Features) -> Result<Btf, BtfError> {
        let mut btf = Btf::new();

        btf.strings = self.strings.to_vec();
        btf.header.str_len = btf.strings.len() as u32;

        // Skip the first type as it's only there
        // to make type_by_id work
        for t in &self.types[1..] {
            let kind = t.kind()?.unwrap_or_default();
            match t {
                BtfType::Var(ty, vars) => {
                    if !features.btf_datasec {
                        debug!("{}: not supported. replacing with INT", kind);
                        let int_type = BtfType::new_int(ty.name_off, 1, 0, 0);
                        btf.add_type(int_type);
                    } else {
                        btf.add_type(BtfType::Var(*ty, *vars));
                    }
                }
                BtfType::DataSec(ty, data) => {
                    if !features.btf_datasec {
                        debug!("{}: not supported. replacing with STRUCT", kind);
                        let members: Vec<btf_member> = data
                            .iter()
                            .map(|p| -> btf_member {
                                let mt = self.type_by_id(p.type_).unwrap();
                                btf_member {
                                    name_off: mt.btf_type().unwrap().name_off,
                                    type_: p.type_,
                                    offset: p.offset * 8,
                                }
                            })
                            .collect();
                        let struct_type = BtfType::new_struct(ty.name_off, members, 0);
                        btf.add_type(struct_type);
                    } else {
                        btf.add_type(BtfType::DataSec(*ty, data.to_vec()));
                    }
                }
                BtfType::FuncProto(ty, vars) => {
                    if !features.btf_func {
                        debug!("{}: not supported. replacing with ENUM", kind);
                        let members: Vec<btf_enum> = vars
                            .iter()
                            .map(|p| -> btf_enum {
                                btf_enum {
                                    name_off: p.name_off,
                                    val: p.type_ as i32,
                                }
                            })
                            .collect();
                        let enum_type = BtfType::new_enum(ty.name_off, members);
                        btf.add_type(enum_type);
                    } else {
                        btf.add_type(BtfType::FuncProto(*ty, vars.to_vec()));
                    }
                }
                BtfType::Func(mut ty) => {
                    if !features.btf_func {
                        debug!("{}: not supported. replacing with TYPEDEF", kind);
                        let typedef_type =
                            BtfType::new_typedef(ty.name_off, unsafe { ty.__bindgen_anon_1.type_ });
                        btf.add_type(typedef_type);
                    } else if type_vlen(&ty) == btf_func_linkage::BTF_FUNC_GLOBAL as usize
                        && !features.btf_func_global
                    {
                        debug!(
                            "{}: BTF_FUNC_GLOBAL not supported. replacing with BTF_FUNC_STATIC",
                            kind
                        );
                        ty.info = (ty.info & 0xFFFF0000)
                            | (btf_func_linkage::BTF_FUNC_STATIC as u32) & 0xFFFF;
                        btf.add_type(BtfType::Func(ty));
                    } else {
                        btf.add_type(BtfType::Func(ty));
                    }
                }
                BtfType::Float(ty) => {
                    if !features.btf_float {
                        debug!("{}: not supported. replacing with STRUCT", kind);
                        let struct_ty =
                            BtfType::new_struct(0, vec![], unsafe { ty.__bindgen_anon_1.size });
                        btf.add_type(struct_ty);
                    } else {
                        btf.add_type(BtfType::Float(*ty));
                    }
                }
                BtfType::DeclTag(ty, btf_decl_tag) => {
                    if !features.btf_decl_tag {
                        debug!("{}: not supported. replacing with INT", kind);
                        let int_type = BtfType::new_int(ty.name_off, 1, 0, 0);
                        btf.add_type(int_type);
                    } else {
                        btf.add_type(BtfType::DeclTag(*ty, *btf_decl_tag));
                    }
                }
                BtfType::TypeTag(ty) => {
                    if !features.btf_type_tag {
                        debug!("{}: not supported. replacing with CONST", kind);
                        let const_type = BtfType::new_const(unsafe { ty.__bindgen_anon_1.type_ });
                        btf.add_type(const_type);
                    } else {
                        btf.add_type(BtfType::TypeTag(*ty));
                    }
                }
                // The type does not need sanitizing
                ty => {
                    btf.add_type(ty.clone());
                }
            }
        }
        Ok(btf)
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

#[derive(Debug)]
pub(crate) struct SecInfo<'a> {
    sec_name_off: u32,
    num_info: u32,
    data: &'a [u8],
}

#[cfg(test)]
mod tests {
    use crate::generated::{btf_param, btf_var_secinfo, BTF_INT_SIGNED, BTF_VAR_STATIC};

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
    fn test_sanitize_btf() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("int".to_string());
        let int_type = BtfType::new_int(name_offset, 4, BTF_INT_SIGNED, 0);
        let int_type_id = btf.add_type(int_type);

        let name_offset = btf.add_string("foo".to_string());
        let var_type = BtfType::new_var(name_offset, int_type_id, BTF_VAR_STATIC);
        let var_type_id = btf.add_type(var_type);

        let name_offset = btf.add_string(".data".to_string());
        let variables = vec![btf_var_secinfo {
            type_: var_type_id,
            offset: 0,
            size: 4,
        }];
        let datasec_type = BtfType::new_datasec(name_offset, variables, 4);
        btf.add_type(datasec_type);

        let name_offset = btf.add_string("float".to_string());
        let float_type = BtfType::new_float(name_offset, 16);
        btf.add_type(float_type);

        let a_name = btf.add_string("a".to_string());
        let b_name = btf.add_string("b".to_string());
        let params = vec![
            btf_param {
                name_off: a_name,
                type_: int_type_id,
            },
            btf_param {
                name_off: b_name,
                type_: int_type_id,
            },
        ];
        let func_proto = BtfType::new_func_proto(params, int_type_id);
        let func_proto_type_id = btf.add_type(func_proto);

        let add = btf.add_string("static".to_string());
        let func = BtfType::new_func(add, func_proto_type_id, btf_func_linkage::BTF_FUNC_STATIC);
        btf.add_type(func);

        let c_name = btf.add_string("c".to_string());
        let d_name = btf.add_string("d".to_string());
        let params = vec![
            btf_param {
                name_off: c_name,
                type_: int_type_id,
            },
            btf_param {
                name_off: d_name,
                type_: int_type_id,
            },
        ];
        let func_proto = BtfType::new_func_proto(params, int_type_id);
        let func_proto_type_id = btf.add_type(func_proto);

        let add = btf.add_string("global".to_string());
        let func = BtfType::new_func(add, func_proto_type_id, btf_func_linkage::BTF_FUNC_GLOBAL);
        btf.add_type(func);

        let name_offset = btf.add_string("int".to_string());
        let type_tag = BtfType::new_type_tag(name_offset, int_type_id);
        btf.add_type(type_tag);

        let name_offset = btf.add_string("decl_tag".to_string());
        let decl_tag = BtfType::new_decl_tag(name_offset, var_type_id, -1);
        btf.add_type(decl_tag);

        let cases = HashMap::from([
            (
                "noop",
                Features {
                    bpf_name: true,
                    btf: true,
                    btf_func: true,
                    btf_func_global: true,
                    btf_datasec: true,
                    btf_float: true,
                    btf_decl_tag: true,
                    btf_type_tag: true,
                },
            ),
            (
                "no datasec",
                Features {
                    bpf_name: true,
                    btf: true,
                    btf_func: true,
                    btf_func_global: true,
                    btf_datasec: false,
                    btf_float: true,
                    btf_decl_tag: true,
                    btf_type_tag: true,
                },
            ),
            (
                "no float",
                Features {
                    bpf_name: true,
                    btf: true,
                    btf_func: true,
                    btf_func_global: true,
                    btf_datasec: true,
                    btf_float: false,
                    btf_decl_tag: true,
                    btf_type_tag: true,
                },
            ),
            (
                "no func",
                Features {
                    bpf_name: true,
                    btf: true,
                    btf_func: false,
                    btf_func_global: true,
                    btf_datasec: true,
                    btf_float: true,
                    btf_decl_tag: true,
                    btf_type_tag: true,
                },
            ),
            (
                "no global func",
                Features {
                    bpf_name: true,
                    btf: true,
                    btf_func: true,
                    btf_func_global: false,
                    btf_datasec: true,
                    btf_float: true,
                    btf_decl_tag: true,
                    btf_type_tag: true,
                },
            ),
            (
                "no decl tag",
                Features {
                    bpf_name: true,
                    btf: true,
                    btf_func: true,
                    btf_func_global: true,
                    btf_datasec: true,
                    btf_float: true,
                    btf_decl_tag: false,
                    btf_type_tag: true,
                },
            ),
            (
                "no type tag",
                Features {
                    bpf_name: true,
                    btf: true,
                    btf_func: true,
                    btf_func_global: true,
                    btf_datasec: true,
                    btf_float: true,
                    btf_decl_tag: true,
                    btf_type_tag: false,
                },
            ),
            (
                "all off",
                Features {
                    bpf_name: true,
                    btf: true,
                    btf_func: false,
                    btf_func_global: false,
                    btf_datasec: false,
                    btf_float: false,
                    btf_decl_tag: false,
                    btf_type_tag: false,
                },
            ),
        ]);

        for (name, features) in cases {
            println!("[CASE] Sanitize {}", name);
            let new_btf = btf.sanitize(&features).unwrap();
            let raw_new_btf = new_btf.to_bytes();
            Btf::parse(&raw_new_btf, Endianness::default()).unwrap();
        }
    }
}
