use std::{
    convert::{TryFrom, TryInto},
    mem, ptr,
};

use object::Endianness;

use crate::{
    generated::{
        btf_array, btf_enum, btf_member, btf_param, btf_type, btf_type__bindgen_ty_1, btf_var,
        btf_var_secinfo, BTF_KIND_ARRAY, BTF_KIND_CONST, BTF_KIND_DATASEC, BTF_KIND_ENUM,
        BTF_KIND_FUNC, BTF_KIND_FUNC_PROTO, BTF_KIND_FWD, BTF_KIND_INT, BTF_KIND_PTR,
        BTF_KIND_RESTRICT, BTF_KIND_STRUCT, BTF_KIND_TYPEDEF, BTF_KIND_UNION, BTF_KIND_UNKN,
        BTF_KIND_VAR, BTF_KIND_VOLATILE,
    },
    obj::btf::{Btf, BtfError, MAX_RESOLVE_DEPTH},
};

#[derive(Clone, Debug)]
pub(crate) enum BtfType {
    Unknown,
    Fwd(btf_type),
    Const(btf_type),
    Volatile(btf_type),
    Restrict(btf_type),
    Ptr(btf_type),
    Typedef(btf_type),
    Func(btf_type),
    Int(btf_type, u32),
    Enum(btf_type, Vec<btf_enum>),
    Array(btf_type, btf_array),
    Struct(btf_type, Vec<btf_member>),
    Union(btf_type, Vec<btf_member>),
    FuncProto(btf_type, Vec<btf_param>),
    Var(btf_type, btf_var),
    DataSec(btf_type, Vec<btf_var_secinfo>),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(crate) enum BtfKind {
    Unknown = BTF_KIND_UNKN,
    Int = BTF_KIND_INT,
    Ptr = BTF_KIND_PTR,
    Array = BTF_KIND_ARRAY,
    Struct = BTF_KIND_STRUCT,
    Union = BTF_KIND_UNION,
    Enum = BTF_KIND_ENUM,
    Fwd = BTF_KIND_FWD,
    Typedef = BTF_KIND_TYPEDEF,
    Volatile = BTF_KIND_VOLATILE,
    Const = BTF_KIND_CONST,
    Restrict = BTF_KIND_RESTRICT,
    Func = BTF_KIND_FUNC,
    FuncProto = BTF_KIND_FUNC_PROTO,
    Var = BTF_KIND_VAR,
    DataSec = BTF_KIND_DATASEC,
}

impl TryFrom<u32> for BtfKind {
    type Error = BtfError;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        use BtfKind::*;
        Ok(match v {
            BTF_KIND_UNKN => Unknown,
            BTF_KIND_INT => Int,
            BTF_KIND_PTR => Ptr,
            BTF_KIND_ARRAY => Array,
            BTF_KIND_STRUCT => Struct,
            BTF_KIND_UNION => Union,
            BTF_KIND_ENUM => Enum,
            BTF_KIND_FWD => Fwd,
            BTF_KIND_TYPEDEF => Typedef,
            BTF_KIND_VOLATILE => Volatile,
            BTF_KIND_CONST => Const,
            BTF_KIND_RESTRICT => Restrict,
            BTF_KIND_FUNC => Func,
            BTF_KIND_FUNC_PROTO => FuncProto,
            BTF_KIND_VAR => Var,
            BTF_KIND_DATASEC => DataSec,
            kind => return Err(BtfError::InvalidTypeKind { kind }),
        })
    }
}

unsafe fn read<T>(data: &[u8]) -> Result<T, BtfError> {
    if mem::size_of::<T>() > data.len() {
        return Err(BtfError::InvalidTypeInfo);
    }

    Ok(ptr::read_unaligned::<T>(data.as_ptr() as *const T))
}

unsafe fn read_array<T>(data: &[u8], len: usize) -> Result<Vec<T>, BtfError> {
    if mem::size_of::<T>() * len > data.len() {
        return Err(BtfError::InvalidTypeInfo);
    }

    Ok((0..len)
        .map(|i| {
            ptr::read_unaligned::<T>((data.as_ptr() as usize + i * mem::size_of::<T>()) as *const T)
        })
        .collect::<Vec<T>>())
}

impl BtfType {
    #[allow(unused_unsafe)]
    pub(crate) unsafe fn read(data: &[u8], endianness: Endianness) -> Result<BtfType, BtfError> {
        let ty = unsafe { read::<btf_type>(data)? };
        let data = &data[mem::size_of::<btf_type>()..];

        let vlen = type_vlen(&ty) as usize;
        use BtfType::*;
        Ok(match type_kind(&ty)? {
            BtfKind::Unknown => Unknown,
            BtfKind::Fwd => Fwd(ty),
            BtfKind::Const => Const(ty),
            BtfKind::Volatile => Volatile(ty),
            BtfKind::Restrict => Restrict(ty),
            BtfKind::Ptr => Ptr(ty),
            BtfKind::Typedef => Typedef(ty),
            BtfKind::Func => Func(ty),
            BtfKind::Int => {
                if mem::size_of::<u32>() > data.len() {
                    return Err(BtfError::InvalidTypeInfo);
                }
                let read_u32 = if endianness == Endianness::Little {
                    u32::from_le_bytes
                } else {
                    u32::from_be_bytes
                };
                Int(
                    ty,
                    read_u32(data[..mem::size_of::<u32>()].try_into().unwrap()),
                )
            }
            BtfKind::Enum => Enum(ty, unsafe { read_array(data, vlen)? }),
            BtfKind::Array => Array(ty, unsafe { read(data)? }),
            BtfKind::Struct => Struct(ty, unsafe { read_array(data, vlen)? }),
            BtfKind::Union => Union(ty, unsafe { read_array(data, vlen)? }),
            BtfKind::FuncProto => FuncProto(ty, unsafe { read_array(data, vlen)? }),
            BtfKind::Var => Var(ty, unsafe { read(data)? }),
            BtfKind::DataSec => DataSec(ty, unsafe { read_array(data, vlen)? }),
        })
    }

    pub(crate) fn type_info_size(&self) -> usize {
        let ty_size = mem::size_of::<btf_type>();

        use BtfType::*;
        match self {
            Unknown => 0,
            Fwd(_) | Const(_) | Volatile(_) | Restrict(_) | Ptr(_) | Typedef(_) | Func(_) => {
                ty_size
            }
            Int(_, _) => ty_size + mem::size_of::<u32>(),
            Enum(ty, _) => ty_size + type_vlen(ty) * mem::size_of::<btf_enum>(),
            Array(_, _) => ty_size + mem::size_of::<btf_array>(),
            Struct(ty, _) => ty_size + type_vlen(ty) * mem::size_of::<btf_member>(),
            Union(ty, _) => ty_size + type_vlen(ty) * mem::size_of::<btf_member>(),
            FuncProto(ty, _) => ty_size + type_vlen(ty) * mem::size_of::<btf_param>(),
            Var(_, _) => ty_size + mem::size_of::<btf_var>(),
            DataSec(ty, _) => ty_size + type_vlen(ty) * mem::size_of::<btf_var_secinfo>(),
        }
    }

    pub(crate) fn btf_type(&self) -> Option<&btf_type> {
        use BtfType::*;
        Some(match self {
            Unknown => return None,
            Fwd(ty) => ty,
            Const(ty) => ty,
            Volatile(ty) => ty,
            Restrict(ty) => ty,
            Ptr(ty) => ty,
            Typedef(ty) => ty,
            Func(ty) => ty,
            Int(ty, _) => ty,
            Enum(ty, _) => ty,
            Array(ty, _) => ty,
            Struct(ty, _) => ty,
            Union(ty, _) => ty,
            FuncProto(ty, _) => ty,
            Var(ty, _) => ty,
            DataSec(ty, _) => ty,
        })
    }

    pub(crate) fn info(&self) -> Option<u32> {
        self.btf_type().map(|ty| ty.info)
    }

    pub(crate) fn name_offset(&self) -> Option<u32> {
        self.btf_type().map(|ty| ty.name_off)
    }

    pub(crate) fn kind(&self) -> Result<Option<BtfKind>, BtfError> {
        self.btf_type().map(type_kind).transpose()
    }

    pub(crate) fn is_composite(&self) -> bool {
        matches!(self, BtfType::Struct(_, _) | BtfType::Union(_, _))
    }
}

fn type_kind(ty: &btf_type) -> Result<BtfKind, BtfError> {
    ((ty.info >> 24) & 0x0F).try_into()
}

fn type_vlen(ty: &btf_type) -> usize {
    (ty.info & 0xFFFF) as usize
}

pub(crate) fn member_bit_offset(info: u32, member: &btf_member) -> usize {
    let k_flag = info >> 31 == 1;
    let bit_offset = if k_flag {
        member.offset & 0xFFFFFF
    } else {
        member.offset
    };

    bit_offset as usize
}

pub(crate) fn member_bit_field_size(ty: &btf_type, member: &btf_member) -> usize {
    let k_flag = (ty.info >> 31) == 1;
    let size = if k_flag { member.offset >> 24 } else { 0 };

    size as usize
}

pub(crate) fn types_are_compatible(
    local_btf: &Btf,
    root_local_id: u32,
    target_btf: &Btf,
    root_target_id: u32,
) -> Result<bool, BtfError> {
    let mut local_id = root_local_id;
    let mut target_id = root_target_id;
    let local_ty = local_btf.type_by_id(local_id)?;
    let target_ty = target_btf.type_by_id(target_id)?;

    if local_ty.kind()? != target_ty.kind()? {
        return Ok(false);
    }

    for _ in 0..MAX_RESOLVE_DEPTH {
        local_id = local_btf.resolve_type(local_id)?;
        target_id = target_btf.resolve_type(target_id)?;
        let local_ty = local_btf.type_by_id(local_id)?;
        let target_ty = target_btf.type_by_id(target_id)?;

        if local_ty.kind()? != target_ty.kind()? {
            return Ok(false);
        }

        use BtfType::*;
        match local_ty {
            Unknown | Struct(_, _) | Union(_, _) | Enum(_, _) | Fwd(_) => return Ok(true),
            Int(_, local_off) => {
                if let Int(_, target_off) = target_ty {
                    return Ok(*local_off == 0 && *target_off == 0);
                }
            }
            Ptr(l_ty) => {
                if let Ptr(t_ty) = target_ty {
                    // Safety: union
                    unsafe {
                        local_id = l_ty.__bindgen_anon_1.type_;
                        target_id = t_ty.__bindgen_anon_1.type_;
                    }
                    continue;
                }
            }
            Array(l_ty, _) => {
                if let Array(t_ty, _) = target_ty {
                    // Safety: union
                    unsafe {
                        local_id = l_ty.__bindgen_anon_1.type_;
                        target_id = t_ty.__bindgen_anon_1.type_;
                    }
                    continue;
                }
            }
            FuncProto(l_ty, l_params) => {
                if let FuncProto(t_ty, t_params) = target_ty {
                    if l_params.len() != t_params.len() {
                        return Ok(false);
                    }

                    for (l_param, t_param) in l_params.iter().zip(t_params.iter()) {
                        let local_id = local_btf.resolve_type(l_param.type_)?;
                        let target_id = target_btf.resolve_type(t_param.type_)?;
                        if !types_are_compatible(local_btf, local_id, target_btf, target_id)? {
                            return Ok(false);
                        }
                    }

                    // Safety: union
                    unsafe {
                        local_id = l_ty.__bindgen_anon_1.type_;
                        target_id = t_ty.__bindgen_anon_1.type_;
                    }
                    continue;
                }
            }
            _ => panic!("this shouldn't be reached"),
        }
    }

    Err(BtfError::MaximumTypeDepthReached { type_id: local_id })
}

pub(crate) fn fields_are_compatible(
    local_btf: &Btf,
    mut local_id: u32,
    target_btf: &Btf,
    mut target_id: u32,
) -> Result<bool, BtfError> {
    for _ in 0..MAX_RESOLVE_DEPTH {
        local_id = local_btf.resolve_type(local_id)?;
        target_id = target_btf.resolve_type(target_id)?;
        let local_ty = local_btf.type_by_id(local_id)?;
        let target_ty = target_btf.type_by_id(target_id)?;

        if local_ty.is_composite() && target_ty.is_composite() {
            return Ok(true);
        }

        if local_ty.kind()? != target_ty.kind()? {
            return Ok(false);
        }

        use BtfType::*;
        match local_ty {
            Fwd(_) | Enum(_, _) => {
                let flavorless_name =
                    |name: &str| name.splitn(2, "___").next().unwrap().to_string();

                let local_name = flavorless_name(&*local_btf.type_name(local_ty)?.unwrap());
                let target_name = flavorless_name(&*target_btf.type_name(target_ty)?.unwrap());

                return Ok(local_name == target_name);
            }
            Int(_, local_off) => {
                let local_off = (local_off >> 16) & 0xFF;
                if let Int(_, target_off) = target_ty {
                    let target_off = (target_off >> 16) & 0xFF;
                    return Ok(local_off == 0 && target_off == 0);
                }
            }
            Ptr(_) => return Ok(true),
            Array(l_ty, _) => {
                if let Array(t_ty, _) = target_ty {
                    // Safety: union
                    unsafe {
                        local_id = l_ty.__bindgen_anon_1.type_;
                        target_id = t_ty.__bindgen_anon_1.type_;
                    }
                    continue;
                }
            }
            _ => panic!("this shouldn't be reached"),
        }
    }

    Err(BtfError::MaximumTypeDepthReached { type_id: local_id })
}

impl std::fmt::Debug for btf_type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("btf_type")
            .field("name_off", &self.name_off)
            .field("info", &self.info)
            .field("__bindgen_anon_1", &self.__bindgen_anon_1)
            .finish()
    }
}

impl std::fmt::Debug for btf_type__bindgen_ty_1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Safety: union
        f.debug_struct("btf_type__bindgen_ty_1")
            .field("size", unsafe { &self.size })
            .field("type_", unsafe { &self.type_ })
            .finish()
    }
}
