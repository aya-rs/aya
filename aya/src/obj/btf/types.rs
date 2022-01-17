use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
    mem, ptr,
};

use object::Endianness;

use crate::{
    generated::{
        btf_array, btf_decl_tag, btf_enum, btf_func_linkage, btf_member, btf_param, btf_type,
        btf_type__bindgen_ty_1, btf_var, btf_var_secinfo, BTF_KIND_ARRAY, BTF_KIND_CONST,
        BTF_KIND_DATASEC, BTF_KIND_DECL_TAG, BTF_KIND_ENUM, BTF_KIND_FLOAT, BTF_KIND_FUNC,
        BTF_KIND_FUNC_PROTO, BTF_KIND_FWD, BTF_KIND_INT, BTF_KIND_PTR, BTF_KIND_RESTRICT,
        BTF_KIND_STRUCT, BTF_KIND_TYPEDEF, BTF_KIND_TYPE_TAG, BTF_KIND_UNION, BTF_KIND_UNKN,
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
    Float(btf_type),
    Enum(btf_type, Vec<btf_enum>),
    Array(btf_type, btf_array),
    Struct(btf_type, Vec<btf_member>),
    Union(btf_type, Vec<btf_member>),
    FuncProto(btf_type, Vec<btf_param>),
    Var(btf_type, btf_var),
    DataSec(btf_type, Vec<btf_var_secinfo>),
    DeclTag(btf_type, btf_decl_tag),
    TypeTag(btf_type),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(crate) enum BtfKind {
    Unknown = BTF_KIND_UNKN,
    Int = BTF_KIND_INT,
    Float = BTF_KIND_FLOAT,
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
    DeclTag = BTF_KIND_DECL_TAG,
    TypeTag = BTF_KIND_TYPE_TAG,
}

impl TryFrom<u32> for BtfKind {
    type Error = BtfError;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        use BtfKind::*;
        Ok(match v {
            BTF_KIND_UNKN => Unknown,
            BTF_KIND_INT => Int,
            BTF_KIND_FLOAT => Float,
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
            BTF_KIND_DECL_TAG => DeclTag,
            BTF_KIND_TYPE_TAG => TypeTag,
            kind => return Err(BtfError::InvalidTypeKind { kind }),
        })
    }
}

impl Display for BtfKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BtfKind::Unknown => write!(f, "[UNKNOWN]"),
            BtfKind::Int => write!(f, "[INT]"),
            BtfKind::Float => write!(f, "[FLOAT]"),
            BtfKind::Ptr => write!(f, "[PTR]"),
            BtfKind::Array => write!(f, "[ARRAY]"),
            BtfKind::Struct => write!(f, "[STRUCT]"),
            BtfKind::Union => write!(f, "[UNION]"),
            BtfKind::Enum => write!(f, "[ENUM]"),
            BtfKind::Fwd => write!(f, "[FWD]"),
            BtfKind::Typedef => write!(f, "[TYPEDEF]"),
            BtfKind::Volatile => write!(f, "[VOLATILE]"),
            BtfKind::Const => write!(f, "[CONST]"),
            BtfKind::Restrict => write!(f, "[RESTRICT]"),
            BtfKind::Func => write!(f, "[FUNC]"),
            BtfKind::FuncProto => write!(f, "[FUNC_PROTO]"),
            BtfKind::Var => write!(f, "[VAR]"),
            BtfKind::DataSec => write!(f, "[DATASEC]"),
            BtfKind::DeclTag => write!(f, "[DECL_TAG]"),
            BtfKind::TypeTag => write!(f, "[TYPE_TAG]"),
        }
    }
}

impl Default for BtfKind {
    fn default() -> Self {
        BtfKind::Unknown
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
            BtfKind::Float => Float(ty),
            BtfKind::Enum => Enum(ty, unsafe { read_array(data, vlen)? }),
            BtfKind::Array => Array(ty, unsafe { read(data)? }),
            BtfKind::Struct => Struct(ty, unsafe { read_array(data, vlen)? }),
            BtfKind::Union => Union(ty, unsafe { read_array(data, vlen)? }),
            BtfKind::FuncProto => FuncProto(ty, unsafe { read_array(data, vlen)? }),
            BtfKind::Var => Var(ty, unsafe { read(data)? }),
            BtfKind::DataSec => DataSec(ty, unsafe { read_array(data, vlen)? }),
            BtfKind::DeclTag => DeclTag(ty, unsafe { read(data)? }),
            BtfKind::TypeTag => TypeTag(ty),
        })
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        fn bytes_of<T>(val: &T) -> &[u8] {
            // Safety: all btf types are POD
            unsafe { crate::util::bytes_of(val) }
        }
        match self {
            BtfType::Fwd(btf_type)
            | BtfType::Const(btf_type)
            | BtfType::Volatile(btf_type)
            | BtfType::Restrict(btf_type)
            | BtfType::Ptr(btf_type)
            | BtfType::Typedef(btf_type)
            | BtfType::Func(btf_type)
            | BtfType::Float(btf_type)
            | BtfType::TypeTag(btf_type) => bytes_of::<btf_type>(btf_type).to_vec(),
            BtfType::Int(btf_type, len) => {
                let mut buf = bytes_of::<btf_type>(btf_type).to_vec();
                buf.append(&mut len.to_ne_bytes().to_vec());
                buf
            }
            BtfType::Enum(btf_type, enums) => {
                let mut buf = bytes_of::<btf_type>(btf_type).to_vec();
                for en in enums {
                    buf.append(&mut bytes_of::<btf_enum>(en).to_vec());
                }
                buf
            }
            BtfType::Array(btf_type, btf_array) => {
                let mut buf = bytes_of::<btf_type>(btf_type).to_vec();
                buf.append(&mut bytes_of::<btf_array>(btf_array).to_vec());
                buf
            }
            BtfType::Struct(btf_type, btf_members) | BtfType::Union(btf_type, btf_members) => {
                let mut buf = bytes_of::<btf_type>(btf_type).to_vec();
                for m in btf_members {
                    buf.append(&mut bytes_of::<btf_member>(m).to_vec());
                }
                buf
            }
            BtfType::FuncProto(btf_type, btf_params) => {
                let mut buf = bytes_of::<btf_type>(btf_type).to_vec();
                for p in btf_params {
                    buf.append(&mut bytes_of::<btf_param>(p).to_vec());
                }
                buf
            }
            BtfType::Var(btf_type, btf_var) => {
                let mut buf = bytes_of::<btf_type>(btf_type).to_vec();
                buf.append(&mut bytes_of::<btf_var>(btf_var).to_vec());
                buf
            }
            BtfType::DataSec(btf_type, btf_var_secinfo) => {
                let mut buf = bytes_of::<btf_type>(btf_type).to_vec();
                for s in btf_var_secinfo {
                    buf.append(&mut bytes_of::<btf_var_secinfo>(s).to_vec());
                }
                buf
            }
            BtfType::Unknown => vec![],
            BtfType::DeclTag(btf_type, btf_decl_tag) => {
                let mut buf = bytes_of::<btf_type>(btf_type).to_vec();
                buf.append(&mut bytes_of::<btf_decl_tag>(btf_decl_tag).to_vec());
                buf
            }
        }
    }

    pub(crate) fn type_info_size(&self) -> usize {
        let ty_size = mem::size_of::<btf_type>();

        use BtfType::*;
        match self {
            Unknown => ty_size,
            Fwd(_) | Const(_) | Volatile(_) | Restrict(_) | Ptr(_) | Typedef(_) | Func(_)
            | Float(_) | TypeTag(_) => ty_size,
            Int(_, _) => ty_size + mem::size_of::<u32>(),
            Enum(ty, _) => ty_size + type_vlen(ty) * mem::size_of::<btf_enum>(),
            Array(_, _) => ty_size + mem::size_of::<btf_array>(),
            Struct(ty, _) => ty_size + type_vlen(ty) * mem::size_of::<btf_member>(),
            Union(ty, _) => ty_size + type_vlen(ty) * mem::size_of::<btf_member>(),
            FuncProto(ty, _) => ty_size + type_vlen(ty) * mem::size_of::<btf_param>(),
            Var(_, _) => ty_size + mem::size_of::<btf_var>(),
            DataSec(ty, _) => ty_size + type_vlen(ty) * mem::size_of::<btf_var_secinfo>(),
            DeclTag(_, _) => ty_size + mem::size_of::<btf_decl_tag>(),
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
            Float(ty) => ty,
            Enum(ty, _) => ty,
            Array(ty, _) => ty,
            Struct(ty, _) => ty,
            Union(ty, _) => ty,
            FuncProto(ty, _) => ty,
            Var(ty, _) => ty,
            DataSec(ty, _) => ty,
            DeclTag(ty, _) => ty,
            TypeTag(ty) => ty,
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

    pub(crate) fn new_int(name_off: u32, size: u32, encoding: u32, offset: u32) -> BtfType {
        let info = (BTF_KIND_INT) << 24;
        let mut btf_type = unsafe { std::mem::zeroed::<btf_type>() };
        btf_type.name_off = name_off;
        btf_type.info = info;
        btf_type.__bindgen_anon_1.size = size;

        let mut data = 0u32;
        data |= (encoding & 0x0f) << 24;
        data |= (offset & 0xff) << 16;
        data |= (size * 8) & 0xff;
        BtfType::Int(btf_type, data)
    }

    pub(crate) fn new_func(name_off: u32, proto: u32, linkage: btf_func_linkage) -> BtfType {
        let mut info = (BTF_KIND_FUNC) << 24;
        info |= (linkage as u32) & 0xFFFF;
        let mut btf_type = unsafe { std::mem::zeroed::<btf_type>() };
        btf_type.name_off = name_off;
        btf_type.info = info;
        btf_type.__bindgen_anon_1.type_ = proto;
        BtfType::Func(btf_type)
    }

    pub(crate) fn new_func_proto(params: Vec<btf_param>, return_type: u32) -> BtfType {
        let mut info = (BTF_KIND_FUNC_PROTO) << 24;
        info |= (params.len() as u32) & 0xFFFF;
        let mut btf_type = unsafe { std::mem::zeroed::<btf_type>() };
        btf_type.name_off = 0;
        btf_type.info = info;
        btf_type.__bindgen_anon_1.type_ = return_type;
        BtfType::FuncProto(btf_type, params)
    }

    pub(crate) fn new_var(name_off: u32, type_: u32, linkage: u32) -> BtfType {
        let info = (BTF_KIND_VAR) << 24;
        let mut btf_type = unsafe { std::mem::zeroed::<btf_type>() };
        btf_type.name_off = name_off;
        btf_type.info = info;
        btf_type.__bindgen_anon_1.type_ = type_;
        let var = btf_var { linkage };
        BtfType::Var(btf_type, var)
    }

    pub(crate) fn new_datasec(
        name_off: u32,
        variables: Vec<btf_var_secinfo>,
        size: u32,
    ) -> BtfType {
        let mut info = (BTF_KIND_DATASEC) << 24;
        info |= (variables.len() as u32) & 0xFFFF;
        let mut btf_type = unsafe { std::mem::zeroed::<btf_type>() };
        btf_type.name_off = name_off;
        btf_type.info = info;
        btf_type.__bindgen_anon_1.size = size;
        BtfType::DataSec(btf_type, variables)
    }

    pub(crate) fn new_float(name_off: u32, size: u32) -> BtfType {
        let info = (BTF_KIND_FLOAT) << 24;
        let mut btf_type = unsafe { std::mem::zeroed::<btf_type>() };
        btf_type.name_off = name_off;
        btf_type.info = info;
        btf_type.__bindgen_anon_1.size = size;
        BtfType::Float(btf_type)
    }

    pub(crate) fn new_struct(name_off: u32, members: Vec<btf_member>, size: u32) -> BtfType {
        let mut info = (BTF_KIND_STRUCT) << 24;
        info |= (members.len() as u32) & 0xFFFF;
        let mut btf_type = unsafe { std::mem::zeroed::<btf_type>() };
        btf_type.name_off = name_off;
        btf_type.info = info;
        btf_type.__bindgen_anon_1.size = size;
        BtfType::Struct(btf_type, members)
    }

    pub(crate) fn new_enum(name_off: u32, members: Vec<btf_enum>) -> BtfType {
        let mut info = (BTF_KIND_ENUM) << 24;
        info |= (members.len() as u32) & 0xFFFF;
        let mut btf_type = unsafe { std::mem::zeroed::<btf_type>() };
        btf_type.name_off = name_off;
        btf_type.info = info;
        btf_type.__bindgen_anon_1.size = 4;
        BtfType::Enum(btf_type, members)
    }

    pub(crate) fn new_typedef(name_off: u32, type_: u32) -> BtfType {
        let info = (BTF_KIND_TYPEDEF) << 24;
        let mut btf_type = unsafe { std::mem::zeroed::<btf_type>() };
        btf_type.name_off = name_off;
        btf_type.info = info;
        btf_type.__bindgen_anon_1.type_ = type_;
        BtfType::Typedef(btf_type)
    }

    #[cfg(test)]
    pub(crate) fn new_array(name_off: u32, type_: u32, index_type: u32, nelems: u32) -> BtfType {
        let info = (BTF_KIND_ARRAY) << 24;
        let mut btf_type = unsafe { std::mem::zeroed::<btf_type>() };
        btf_type.name_off = name_off;
        btf_type.info = info;
        let btf_array = btf_array {
            type_,
            index_type,
            nelems,
        };
        BtfType::Array(btf_type, btf_array)
    }

    pub(crate) fn new_decl_tag(name_off: u32, type_: u32, component_idx: i32) -> BtfType {
        let info = (BTF_KIND_DECL_TAG) << 24;
        let mut btf_type = unsafe { std::mem::zeroed::<btf_type>() };
        btf_type.name_off = name_off;
        btf_type.info = info;
        btf_type.__bindgen_anon_1.type_ = type_;
        let btf_decl_tag = btf_decl_tag { component_idx };
        BtfType::DeclTag(btf_type, btf_decl_tag)
    }

    pub(crate) fn new_type_tag(name_off: u32, type_: u32) -> BtfType {
        let info = (BTF_KIND_TYPE_TAG) << 24;
        let mut btf_type = unsafe { std::mem::zeroed::<btf_type>() };
        btf_type.name_off = name_off;
        btf_type.info = info;
        btf_type.__bindgen_anon_1.type_ = type_;
        BtfType::TypeTag(btf_type)
    }

    pub(crate) fn new_ptr(type_: u32) -> BtfType {
        let info = (BTF_KIND_PTR) << 24;
        let mut btf_type = unsafe { std::mem::zeroed::<btf_type>() };
        btf_type.name_off = 0;
        btf_type.info = info;
        btf_type.__bindgen_anon_1.type_ = type_;
        BtfType::Ptr(btf_type)
    }

    pub(crate) fn new_const(type_: u32) -> BtfType {
        let info = (BTF_KIND_CONST) << 24;
        let mut btf_type = unsafe { std::mem::zeroed::<btf_type>() };
        btf_type.name_off = 0;
        btf_type.info = info;
        btf_type.__bindgen_anon_1.type_ = type_;
        BtfType::Const(btf_type)
    }
}

fn type_kind(ty: &btf_type) -> Result<BtfKind, BtfError> {
    ((ty.info >> 24) & 0x1F).try_into()
}

pub(crate) fn type_vlen(ty: &btf_type) -> usize {
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
            Unknown | Struct(_, _) | Union(_, _) | Enum(_, _) | Fwd(_) | Float(_) => {
                return Ok(true)
            }
            Int(_, local_off) => {
                let local_off = (local_off >> 16) & 0xFF;
                if let Int(_, target_off) = target_ty {
                    let target_off = (target_off >> 16) & 0xFF;
                    return Ok(local_off == 0 && target_off == 0);
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
            Array(_, l_ty) => {
                if let Array(_, t_ty) = target_ty {
                    local_id = l_ty.type_;
                    target_id = t_ty.type_;
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
                    |name: &str| name.split_once("___").map_or(name, |x| x.0).to_string();

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
            Float(_) => return Ok(true),
            Ptr(_) => return Ok(true),
            Array(_, l_ty) => {
                if let Array(_, t_ty) = target_ty {
                    local_id = l_ty.type_;
                    target_id = t_ty.type_;

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

#[cfg(test)]
mod tests {
    use crate::generated::BTF_INT_SIGNED;

    use super::*;

    #[test]
    fn test_read_btf_type_int() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::Int(ty, nr_bits)) => {
                assert_eq!(ty.name_off, 1);
                assert_eq!(unsafe { ty.__bindgen_anon_1.size }, 8);
                assert_eq!(nr_bits, 64);
            }
            Ok(t) => panic!("expected int type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice());
    }

    #[test]
    fn test_write_btf_long_unsigned_int() {
        let data: &[u8] = &[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x00, 0x00,
        ];
        let int = BtfType::new_int(1, 8, 0, 0);
        assert_eq!(int.to_bytes(), data);
    }

    #[test]
    fn test_write_btf_uchar() {
        let data: &[u8] = &[
            0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x00, 0x00,
        ];
        let int = BtfType::new_int(0x13, 1, 0, 0);
        assert_eq!(int.to_bytes(), data);
    }

    #[test]
    fn test_write_btf_signed_short_int() {
        let data: &[u8] = &[
            0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x01,
        ];
        let int = BtfType::new_int(0x4a, 2, BTF_INT_SIGNED, 0);
        assert_eq!(int.to_bytes(), data);
    }

    #[test]
    fn test_read_btf_type_ptr() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x06, 0x00, 0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::Ptr(_)) => {}
            Ok(t) => panic!("expected ptr type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_read_btf_type_array() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::Array(_, _)) => {}
            Ok(t) => panic!("expected array type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_read_btf_type_struct() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00, 0x47, 0x02,
            0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::Struct(_, _)) => {}
            Ok(t) => panic!("expected struct type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_read_btf_type_union() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x05, 0x04, 0x00, 0x00, 0x00, 0x0d, 0x04,
            0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::Union(_, _)) => {}
            Ok(t) => panic!("expected union type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_read_btf_type_enum() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0xc9, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::Enum(_, _)) => {}
            Ok(t) => panic!("expected enum type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_read_btf_type_fwd() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0x0b, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::Fwd(_)) => {}
            Ok(t) => panic!("expected fwd type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_read_btf_type_typedef() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x0b, 0x00, 0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::Typedef(_)) => {}
            Ok(t) => panic!("expected typedef type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_read_btf_type_volatile() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x24, 0x00, 0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::Volatile(_)) => {}
            Ok(t) => panic!("expected volatile type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_read_btf_type_const() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::Const(_)) => {}
            Ok(t) => panic!("expected const type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_read_btf_type_restrict() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x04, 0x00, 0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::Restrict(_)) => {}
            Ok(t) => panic!("expected restrict type gpt {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_read_btf_type_func() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0x17, 0x8b, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x0c, 0xf0, 0xe4, 0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::Func(_)) => {}
            Ok(t) => panic!("expected func type gpt {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_read_btf_type_func_proto() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::FuncProto(_, _)) => {}
            Ok(t) => panic!("expected func_proto type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_read_btf_type_func_var() {
        let endianness = Endianness::default();
        // NOTE: There was no data in /sys/kernell/btf/vmlinux for this type
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::Var(_, _)) => {}
            Ok(t) => panic!("expected var type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        };
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_read_btf_type_func_datasec() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0xd9, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match &got {
            Ok(BtfType::DataSec(ty, info)) => {
                assert_eq!(0, unsafe { ty.__bindgen_anon_1.size } as usize);
                assert_eq!(1, type_vlen(ty) as usize);
                assert_eq!(1, info.len());
                assert_eq!(11, info[0].type_);
                assert_eq!(0, info[0].offset);
                assert_eq!(4, info[0].size);
            }
            Ok(t) => panic!("expected datasec type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_read_btf_type_float() {
        let endianness = Endianness::default();
        let data: &[u8] = &[
            0x78, 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00,
        ];
        let got = unsafe { BtfType::read(data, endianness) };
        match got {
            Ok(BtfType::Float(_)) => {}
            Ok(t) => panic!("expected float type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2.as_slice())
    }

    #[test]
    fn test_write_btf_func_proto() {
        let params = vec![
            btf_param {
                name_off: 1,
                type_: 1,
            },
            btf_param {
                name_off: 3,
                type_: 1,
            },
        ];
        let func_proto = BtfType::new_func_proto(params, 2);
        let data = func_proto.to_bytes();
        let got = unsafe { BtfType::read(&data, Endianness::default()) };
        match got {
            Ok(BtfType::FuncProto(btf_type, _params)) => {
                assert_eq!(type_vlen(&btf_type), 2);
            }
            Ok(t) => panic!("expected func proto type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
    }

    #[test]
    fn test_types_are_compatible() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("u32".to_string());
        let u32t = btf.add_type(BtfType::new_int(name_offset, 4, 0, 0));
        let name_offset = btf.add_string("u64".to_string());
        let u64t = btf.add_type(BtfType::new_int(name_offset, 8, 0, 0));
        let name_offset = btf.add_string("widgets".to_string());
        let array_type = btf.add_type(BtfType::new_array(name_offset, u64t, u32t, 16));

        assert!(types_are_compatible(&btf, u32t, &btf, u32t).unwrap());
        // int types are compatible if offsets match. size and encoding aren't compared
        assert!(types_are_compatible(&btf, u32t, &btf, u64t).unwrap());
        assert!(types_are_compatible(&btf, array_type, &btf, array_type).unwrap());
    }
}
