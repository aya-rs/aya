use std::{
    borrow::Cow,
    convert::TryInto,
    ffi::{c_void, CStr},
    fs, io, mem,
    path::{Path, PathBuf},
    ptr,
};

use object::Endianness;
use thiserror::Error;

use crate::{
    generated::{btf_ext_header, btf_header},
    obj::btf::{relocation::Relocation, BtfType},
};

pub(crate) const MAX_RESOLVE_DEPTH: u8 = 32;
pub(crate) const MAX_SPEC_LEN: usize = 64;

/// The error type returned when `BTF` operations fail.
#[derive(Error, Debug)]
pub enum BtfError {
    #[error("error parsing {path}")]
    FileError {
        path: PathBuf,
        #[source]
        error: io::Error,
    },

    #[error("error parsing BTF header")]
    InvalidHeader,

    #[error("invalid BTF type info segment")]
    InvalidTypeInfo,

    #[error("invalid BTF relocation info segment")]
    InvalidRelocationInfo,

    #[error("invalid BTF type kind `{kind}`")]
    InvalidTypeKind { kind: u32 },

    #[error("invalid BTF relocation kind `{kind}`")]
    InvalidRelocationKind { kind: u32 },

    #[error("invalid BTF string offset: {offset}")]
    InvalidStringOffset { offset: usize },

    #[error("invalid BTF info, offset: {offset} len: {len} section_len: {section_len}")]
    InvalidInfo {
        offset: usize,
        len: usize,
        section_len: usize,
    },

    #[error("invalid BTF line info, offset: {offset} len: {len} section_len: {section_len}")]
    InvalidLineInfo {
        offset: usize,
        len: usize,
        section_len: usize,
    },

    #[error("Unknown BTF type id `{type_id}`")]
    UnknownBtfType { type_id: u32 },

    #[error("Unexpected BTF type id `{type_id}`")]
    UnexpectedBtfType { type_id: u32 },

    #[error("maximum depth reached resolving BTF type")]
    MaximumTypeDepthReached { type_id: u32 },
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
    endianness: Endianness,
}

impl Btf {
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
        let header = unsafe { ptr::read_unaligned(data.as_ptr() as *const btf_header) };

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
            endianness,
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
                Volatile(ty) | Const(ty) | Restrict(ty) | Typedef(ty) => {
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

    pub(crate) fn type_size(&self, root_type_id: u32) -> Result<usize, BtfError> {
        let mut type_id = root_type_id;
        let mut n_elems = 1;
        for _ in 0..MAX_RESOLVE_DEPTH {
            let ty = self.type_by_id(type_id)?;

            use BtfType::*;
            let size = match ty {
                Int(ty, _) | Struct(ty, _) | Union(ty, _) | Enum(ty, _) | DataSec(ty, _) => {
                    // Safety: union
                    unsafe { ty.__bindgen_anon_1.size as usize }
                }
                Ptr(_) => mem::size_of::<*const c_void>(), // FIXME
                Typedef(ty) | Volatile(ty) | Const(ty) | Restrict(ty) | Var(ty, _) => {
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
}

#[derive(Debug, Clone)]
pub struct BtfExt {
    data: Vec<u8>,
    endianness: Endianness,
    relocations: Vec<(u32, Vec<Relocation>)>,
    header: btf_ext_header,
    func_info_rec_size: usize,
    line_info_rec_size: usize,
    core_relo_rec_size: usize,
}

impl BtfExt {
    pub(crate) fn parse(data: &[u8], endianness: Endianness) -> Result<BtfExt, BtfError> {
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
            func_info_rec_size: rec_size(func_info_off, func_info_len)?,
            line_info_rec_size: rec_size(line_info_off, line_info_len)?,
            core_relo_rec_size: rec_size(core_relo_off, core_relo_len)?,
            data: data.to_vec(),
            endianness,
        };

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

    pub(crate) fn relocations(&self) -> impl Iterator<Item = &(u32, Vec<Relocation>)> {
        self.relocations.iter()
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
