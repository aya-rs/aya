use std::{fmt::Display, mem, ptr};

use object::Endianness;

use crate::obj::btf::{Btf, BtfError, MAX_RESOLVE_DEPTH};

#[derive(Clone, Debug)]
pub(crate) enum BtfType {
    Unknown,
    Fwd(Fwd),
    Const(Const),
    Volatile(Volatile),
    Restrict(Restrict),
    Ptr(Ptr),
    Typedef(Typedef),
    Func(Func),
    Int(Int),
    Float(Float),
    Enum(Enum),
    Array(Array),
    Struct(Struct),
    Union(Union),
    FuncProto(FuncProto),
    Var(Var),
    DataSec(DataSec),
    DeclTag(DeclTag),
    TypeTag(TypeTag),
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct Fwd {
    pub(crate) name_offset: u32,
    info: u32,
    _unused: u32,
}

impl Fwd {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        bytes_of::<Fwd>(self).to_vec()
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::Fwd
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Self>()
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct Const {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) btf_type: u32,
}

impl Const {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        bytes_of::<Const>(self).to_vec()
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::Const
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Self>()
    }

    pub(crate) fn new(btf_type: u32) -> Self {
        let info = (BtfKind::Const as u32) << 24;
        Const {
            name_offset: 0,
            info,
            btf_type,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct Volatile {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) btf_type: u32,
}

impl Volatile {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        bytes_of::<Volatile>(self).to_vec()
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::Volatile
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Self>()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Restrict {
    pub(crate) name_offset: u32,
    _info: u32,
    pub(crate) btf_type: u32,
}

impl Restrict {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        bytes_of::<Restrict>(self).to_vec()
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::Restrict
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Self>()
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct Ptr {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) btf_type: u32,
}

impl Ptr {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        bytes_of::<Self>(self).to_vec()
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::Ptr
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Self>()
    }

    pub(crate) fn new(name_offset: u32, btf_type: u32) -> Self {
        let info = (BtfKind::Ptr as u32) << 24;
        Ptr {
            name_offset,
            info,
            btf_type,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct Typedef {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) btf_type: u32,
}

impl Typedef {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        bytes_of::<Self>(self).to_vec()
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::Typedef
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Self>()
    }

    pub(crate) fn new(name_offset: u32, btf_type: u32) -> Self {
        let info = (BtfKind::Typedef as u32) << 24;
        Typedef {
            name_offset,
            info,
            btf_type,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct Float {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) size: u32,
}

impl Float {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        bytes_of::<Self>(self).to_vec()
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::Float
    }
    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Self>()
    }

    pub(crate) fn new(name_offset: u32, size: u32) -> Self {
        let info = (BtfKind::Float as u32) << 24;
        Float {
            name_offset,
            info,
            size,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct Func {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) btf_type: u32,
}

#[repr(u32)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FuncLinkage {
    Static = 0,
    Global = 1,
    Extern = 2,
    Unknown,
}

impl From<u32> for FuncLinkage {
    fn from(v: u32) -> Self {
        match v {
            0 => FuncLinkage::Static,
            1 => FuncLinkage::Global,
            2 => FuncLinkage::Extern,
            _ => FuncLinkage::Unknown,
        }
    }
}

impl Func {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        bytes_of::<Self>(self).to_vec()
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::Func
    }
    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Self>()
    }

    pub(crate) fn new(name_offset: u32, proto: u32, linkage: FuncLinkage) -> Self {
        let mut info = (BtfKind::Func as u32) << 24;
        info |= (linkage as u32) & 0xFFFF;
        Func {
            name_offset,
            info,
            btf_type: proto,
        }
    }

    pub(crate) fn linkage(&self) -> FuncLinkage {
        (self.info & 0xFFF).into()
    }

    pub(crate) fn set_linkage(&mut self, linkage: FuncLinkage) {
        self.info = (self.info & 0xFFFF0000) | (linkage as u32) & 0xFFFF;
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct TypeTag {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) btf_type: u32,
}

impl TypeTag {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        bytes_of::<Self>(self).to_vec()
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::TypeTag
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Self>()
    }

    pub(crate) fn new(name_offset: u32, btf_type: u32) -> Self {
        let info = (BtfKind::TypeTag as u32) << 24;
        TypeTag {
            name_offset,
            info,
            btf_type,
        }
    }
}

#[repr(u32)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IntEncoding {
    None,
    Signed = 1,
    Char = 2,
    Bool = 4,
    Unknown,
}

impl From<u32> for IntEncoding {
    fn from(v: u32) -> Self {
        match v {
            0 => IntEncoding::None,
            1 => IntEncoding::Signed,
            2 => IntEncoding::Char,
            4 => IntEncoding::Bool,
            _ => IntEncoding::Unknown,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct Int {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) size: u32,
    pub(crate) data: u32,
}

impl Int {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend(bytes_of::<u32>(&self.name_offset));
        buf.extend(bytes_of::<u32>(&self.info));
        buf.extend(bytes_of::<u32>(&self.size));
        buf.extend(bytes_of::<u32>(&self.data));
        buf
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::Int
    }
    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Self>()
    }

    pub(crate) fn new(name_offset: u32, size: u32, encoding: IntEncoding, offset: u32) -> Self {
        let info = (BtfKind::Int as u32) << 24;
        let mut data = 0u32;
        data |= (encoding as u32 & 0x0f) << 24;
        data |= (offset & 0xff) << 16;
        data |= (size * 8) & 0xff;
        Int {
            name_offset,
            info,
            size,
            data,
        }
    }

    pub(crate) fn encoding(&self) -> IntEncoding {
        ((self.data & 0x0f000000) >> 24).into()
    }

    pub(crate) fn offset(&self) -> u32 {
        (self.data & 0x00ff0000) >> 16
    }

    // TODO: Remove directive this when this crate is pub
    #[cfg(test)]
    pub(crate) fn bits(&self) -> u32 {
        self.data & 0x000000ff
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub(crate) struct BtfEnum {
    pub(crate) name_offset: u32,
    pub(crate) value: i32,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct Enum {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) size: u32,
    pub(crate) variants: Vec<BtfEnum>,
}

impl Enum {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend(bytes_of::<u32>(&self.name_offset));
        buf.extend(bytes_of::<u32>(&self.info));
        buf.extend(bytes_of::<u32>(&self.size));
        for v in &self.variants {
            buf.extend(bytes_of::<u32>(&v.name_offset));
            buf.extend(bytes_of::<i32>(&v.value));
        }
        buf
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::Enum
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Fwd>() + mem::size_of::<BtfEnum>() * self.variants.len()
    }

    pub(crate) fn new(name_offset: u32, variants: Vec<BtfEnum>) -> Self {
        let mut info = (BtfKind::Enum as u32) << 24;
        info |= (variants.len() as u32) & 0xFFFF;
        Enum {
            name_offset,
            info,
            size: 4,
            variants,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct BtfMember {
    pub(crate) name_offset: u32,
    pub(crate) btf_type: u32,
    pub(crate) offset: u32,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct Struct {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) size: u32,
    pub(crate) members: Vec<BtfMember>,
}

impl Struct {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend(bytes_of::<u32>(&self.name_offset));
        buf.extend(bytes_of::<u32>(&self.info));
        buf.extend(bytes_of::<u32>(&self.size));
        for v in &self.members {
            buf.extend(bytes_of::<u32>(&v.name_offset));
            buf.extend(bytes_of::<u32>(&v.btf_type));
            buf.extend(bytes_of::<u32>(&v.offset));
        }
        buf
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::Struct
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Fwd>() + mem::size_of::<BtfMember>() * self.members.len()
    }

    pub(crate) fn new(name_offset: u32, members: Vec<BtfMember>, size: u32) -> Self {
        let mut info = (BtfKind::Struct as u32) << 24;
        info |= (members.len() as u32) & 0xFFFF;
        Struct {
            name_offset,
            info,
            size,
            members,
        }
    }

    pub(crate) fn member_bit_offset(&self, member: &BtfMember) -> usize {
        let k_flag = self.info >> 31 == 1;
        let bit_offset = if k_flag {
            member.offset & 0xFFFFFF
        } else {
            member.offset
        };

        bit_offset as usize
    }

    pub(crate) fn member_bit_field_size(&self, member: &BtfMember) -> usize {
        let k_flag = (self.info >> 31) == 1;
        let size = if k_flag { member.offset >> 24 } else { 0 };

        size as usize
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct Union {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) size: u32,
    pub(crate) members: Vec<BtfMember>,
}

impl Union {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend(bytes_of::<u32>(&self.name_offset));
        buf.extend(bytes_of::<u32>(&self.info));
        buf.extend(bytes_of::<u32>(&self.size));
        for v in &self.members {
            buf.extend(bytes_of::<u32>(&v.name_offset));
            buf.extend(bytes_of::<u32>(&v.btf_type));
            buf.extend(bytes_of::<u32>(&v.offset));
        }
        buf
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::Union
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Fwd>() + mem::size_of::<BtfMember>() * self.members.len()
    }

    pub(crate) fn member_bit_offset(&self, member: &BtfMember) -> usize {
        let k_flag = self.info >> 31 == 1;
        let bit_offset = if k_flag {
            member.offset & 0xFFFFFF
        } else {
            member.offset
        };

        bit_offset as usize
    }

    pub(crate) fn member_bit_field_size(&self, member: &BtfMember) -> usize {
        let k_flag = (self.info >> 31) == 1;
        let size = if k_flag { member.offset >> 24 } else { 0 };

        size as usize
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct BtfArray {
    pub(crate) element_type: u32,
    pub(crate) index_type: u32,
    pub(crate) len: u32,
}
#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct Array {
    pub(crate) name_offset: u32,
    info: u32,
    _unused: u32,
    pub(crate) array: BtfArray,
}

impl Array {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend(bytes_of::<u32>(&self.name_offset));
        buf.extend(bytes_of::<u32>(&self.info));
        buf.extend(bytes_of::<u32>(&self._unused));
        buf.extend(bytes_of::<BtfArray>(&self.array));
        buf
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::Array
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Self>()
    }

    #[cfg(test)]
    pub(crate) fn new(name_offset: u32, element_type: u32, index_type: u32, len: u32) -> Self {
        let info = (BtfKind::Array as u32) << 24;
        Array {
            name_offset,
            info,
            _unused: 0,
            array: BtfArray {
                element_type,
                index_type,
                len,
            },
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct BtfParam {
    pub(crate) name_offset: u32,
    pub(crate) btf_type: u32,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct FuncProto {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) return_type: u32,
    pub(crate) params: Vec<BtfParam>,
}

impl FuncProto {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend(bytes_of::<u32>(&self.name_offset));
        buf.extend(bytes_of::<u32>(&self.info));
        buf.extend(bytes_of::<u32>(&self.return_type));
        for p in &self.params {
            buf.extend(bytes_of::<u32>(&p.name_offset));
            buf.extend(bytes_of::<u32>(&p.btf_type));
        }
        buf
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::FuncProto
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Fwd>() + mem::size_of::<BtfParam>() * self.params.len()
    }

    pub(crate) fn new(params: Vec<BtfParam>, return_type: u32) -> Self {
        let mut info = (BtfKind::FuncProto as u32) << 24;
        info |= (params.len() as u32) & 0xFFFF;
        FuncProto {
            name_offset: 0,
            info,
            return_type,
            params,
        }
    }
}

#[repr(u32)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VarLinkage {
    Static,
    Global,
    Extern,
    Unknown,
}

impl From<u32> for VarLinkage {
    fn from(v: u32) -> Self {
        match v {
            0 => VarLinkage::Static,
            1 => VarLinkage::Global,
            2 => VarLinkage::Extern,
            _ => VarLinkage::Unknown,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct Var {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) btf_type: u32,
    pub(crate) linkage: VarLinkage,
}

impl Var {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend(bytes_of::<u32>(&self.name_offset));
        buf.extend(bytes_of::<u32>(&self.info));
        buf.extend(bytes_of::<u32>(&self.btf_type));
        buf.extend(bytes_of::<VarLinkage>(&self.linkage));
        buf
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::Var
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Self>()
    }

    pub(crate) fn new(name_offset: u32, btf_type: u32, linkage: VarLinkage) -> Self {
        let info = (BtfKind::Var as u32) << 24;
        Var {
            name_offset,
            info,
            btf_type,
            linkage,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct DataSecEntry {
    pub(crate) btf_type: u32,
    pub(crate) offset: u32,
    pub(crate) size: u32,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct DataSec {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) size: u32,
    pub(crate) entries: Vec<DataSecEntry>,
}

impl DataSec {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend(bytes_of::<u32>(&self.name_offset));
        buf.extend(bytes_of::<u32>(&self.info));
        buf.extend(bytes_of::<u32>(&self.size));
        for e in &self.entries {
            buf.extend(bytes_of::<u32>(&e.btf_type));
            buf.extend(bytes_of::<u32>(&e.offset));
            buf.extend(bytes_of::<u32>(&e.size));
        }
        buf
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::DataSec
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Fwd>() + mem::size_of::<DataSecEntry>() * self.entries.len()
    }

    pub(crate) fn new(name_offset: u32, entries: Vec<DataSecEntry>, size: u32) -> Self {
        let mut info = (BtfKind::DataSec as u32) << 24;
        info |= (entries.len() as u32) & 0xFFFF;
        DataSec {
            name_offset,
            info,
            size,
            entries,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct DeclTag {
    pub(crate) name_offset: u32,
    info: u32,
    pub(crate) btf_type: u32,
    pub(crate) component_index: i32,
}

impl DeclTag {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend(bytes_of::<u32>(&self.name_offset));
        buf.extend(bytes_of::<u32>(&self.info));
        buf.extend(bytes_of::<u32>(&self.btf_type));
        buf.extend(bytes_of::<i32>(&self.component_index));
        buf
    }

    pub(crate) fn kind(&self) -> BtfKind {
        BtfKind::DeclTag
    }

    pub(crate) fn type_info_size(&self) -> usize {
        mem::size_of::<Self>()
    }

    pub(crate) fn new(name_offset: u32, btf_type: u32, component_index: i32) -> Self {
        let info = (BtfKind::DeclTag as u32) << 24;
        DeclTag {
            name_offset,
            info,
            btf_type,
            component_index,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(crate) enum BtfKind {
    Unknown = 0,
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    FuncProto = 13,
    Var = 14,
    DataSec = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
}

impl TryFrom<u32> for BtfKind {
    type Error = BtfError;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        use BtfKind::*;
        Ok(match v {
            0 => Unknown,
            1 => Int,
            2 => Ptr,
            3 => Array,
            4 => Struct,
            5 => Union,
            6 => Enum,
            7 => Fwd,
            8 => Typedef,
            9 => Volatile,
            10 => Const,
            11 => Restrict,
            12 => Func,
            13 => FuncProto,
            14 => Var,
            15 => DataSec,
            16 => Float,
            17 => DeclTag,
            18 => TypeTag,
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
    let data = &data[0..mem::size_of::<T>() * len];
    let r = data
        .chunks(mem::size_of::<T>())
        .map(|chunk| ptr::read_unaligned(chunk.as_ptr() as *const T))
        .collect();
    Ok(r)
}

impl BtfType {
    #[allow(unused_unsafe)]
    pub(crate) unsafe fn read(data: &[u8], endianness: Endianness) -> Result<BtfType, BtfError> {
        let ty = unsafe { read_array::<u32>(data, 3)? };
        let data = &data[mem::size_of::<u32>() * 3..];
        let vlen = type_vlen(ty[1]);
        Ok(match type_kind(ty[1])? {
            BtfKind::Unknown => BtfType::Unknown,
            BtfKind::Fwd => BtfType::Fwd(Fwd {
                name_offset: ty[0],
                info: ty[1],
                _unused: 0,
            }),
            BtfKind::Const => BtfType::Const(Const {
                name_offset: ty[0],
                info: ty[1],
                btf_type: ty[2],
            }),
            BtfKind::Volatile => BtfType::Volatile(Volatile {
                name_offset: ty[0],
                info: ty[1],
                btf_type: ty[2],
            }),
            BtfKind::Restrict => BtfType::Restrict(Restrict {
                name_offset: ty[0],
                _info: ty[1],
                btf_type: ty[2],
            }),
            BtfKind::Ptr => BtfType::Ptr(Ptr {
                name_offset: ty[0],
                info: ty[1],
                btf_type: ty[2],
            }),
            BtfKind::Typedef => BtfType::Typedef(Typedef {
                name_offset: ty[0],
                info: ty[1],
                btf_type: ty[2],
            }),
            BtfKind::Func => BtfType::Func(Func {
                name_offset: ty[0],
                info: ty[1],
                btf_type: ty[2],
            }),
            BtfKind::Int => {
                if mem::size_of::<u32>() > data.len() {
                    return Err(BtfError::InvalidTypeInfo);
                }
                let read_u32 = if endianness == Endianness::Little {
                    u32::from_le_bytes
                } else {
                    u32::from_be_bytes
                };
                BtfType::Int(Int {
                    name_offset: ty[0],
                    info: ty[1],
                    size: ty[2],
                    data: read_u32(data[..mem::size_of::<u32>()].try_into().unwrap()),
                })
            }
            BtfKind::Float => BtfType::Float(Float {
                name_offset: ty[0],
                info: ty[1],
                size: ty[2],
            }),
            BtfKind::Enum => BtfType::Enum(Enum {
                name_offset: ty[0],
                info: ty[1],
                size: ty[2],
                variants: unsafe { read_array::<BtfEnum>(data, vlen)? },
            }),
            BtfKind::Array => BtfType::Array(Array {
                name_offset: ty[0],
                info: ty[1],
                _unused: 0,
                array: unsafe { read(data)? },
            }),
            BtfKind::Struct => BtfType::Struct(Struct {
                name_offset: ty[0],
                info: ty[1],
                size: ty[2],
                members: unsafe { read_array::<BtfMember>(data, vlen)? },
            }),
            BtfKind::Union => BtfType::Union(Union {
                name_offset: ty[0],
                info: ty[1],
                size: ty[2],
                members: unsafe { read_array::<BtfMember>(data, vlen)? },
            }),
            BtfKind::FuncProto => BtfType::FuncProto(FuncProto {
                name_offset: ty[0],
                info: ty[1],
                return_type: ty[2],
                params: unsafe { read_array::<BtfParam>(data, vlen)? },
            }),
            BtfKind::Var => BtfType::Var(Var {
                name_offset: ty[0],
                info: ty[1],
                btf_type: ty[2],
                linkage: unsafe { read(data)? },
            }),
            BtfKind::DataSec => BtfType::DataSec(DataSec {
                name_offset: ty[0],
                info: ty[1],
                size: ty[2],
                entries: unsafe { read_array::<DataSecEntry>(data, vlen)? },
            }),
            BtfKind::DeclTag => BtfType::DeclTag(DeclTag {
                name_offset: ty[0],
                info: ty[1],
                btf_type: ty[2],
                component_index: unsafe { read(data)? },
            }),
            BtfKind::TypeTag => BtfType::TypeTag(TypeTag {
                name_offset: ty[0],
                info: ty[1],
                btf_type: ty[2],
            }),
        })
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        match self {
            BtfType::Unknown => vec![],
            BtfType::Fwd(t) => t.to_bytes(),
            BtfType::Const(t) => t.to_bytes(),
            BtfType::Volatile(t) => t.to_bytes(),
            BtfType::Restrict(t) => t.to_bytes(),
            BtfType::Ptr(t) => t.to_bytes(),
            BtfType::Typedef(t) => t.to_bytes(),
            BtfType::Func(t) => t.to_bytes(),
            BtfType::Int(t) => t.to_bytes(),
            BtfType::Float(t) => t.to_bytes(),
            BtfType::Enum(t) => t.to_bytes(),
            BtfType::Array(t) => t.to_bytes(),
            BtfType::Struct(t) => t.to_bytes(),
            BtfType::Union(t) => t.to_bytes(),
            BtfType::FuncProto(t) => t.to_bytes(),
            BtfType::Var(t) => t.to_bytes(),
            BtfType::DataSec(t) => t.to_bytes(),
            BtfType::DeclTag(t) => t.to_bytes(),
            BtfType::TypeTag(t) => t.to_bytes(),
        }
    }

    pub(crate) fn size(&self) -> Option<u32> {
        match self {
            BtfType::Int(t) => Some(t.size),
            BtfType::Float(t) => Some(t.size),
            BtfType::Enum(t) => Some(t.size),
            BtfType::Struct(t) => Some(t.size),
            BtfType::Union(t) => Some(t.size),
            BtfType::DataSec(t) => Some(t.size),
            _ => None,
        }
    }

    pub(crate) fn btf_type(&self) -> Option<u32> {
        match self {
            BtfType::Const(t) => Some(t.btf_type),
            BtfType::Volatile(t) => Some(t.btf_type),
            BtfType::Restrict(t) => Some(t.btf_type),
            BtfType::Ptr(t) => Some(t.btf_type),
            BtfType::Typedef(t) => Some(t.btf_type),
            // FuncProto contains the return type here, and doesn't directly reference another type
            BtfType::FuncProto(t) => Some(t.return_type),
            BtfType::Var(t) => Some(t.btf_type),
            BtfType::DeclTag(t) => Some(t.btf_type),
            BtfType::TypeTag(t) => Some(t.btf_type),
            _ => None,
        }
    }

    pub(crate) fn type_info_size(&self) -> usize {
        match self {
            BtfType::Unknown => mem::size_of::<Fwd>(),
            BtfType::Fwd(t) => t.type_info_size(),
            BtfType::Const(t) => t.type_info_size(),
            BtfType::Volatile(t) => t.type_info_size(),
            BtfType::Restrict(t) => t.type_info_size(),
            BtfType::Ptr(t) => t.type_info_size(),
            BtfType::Typedef(t) => t.type_info_size(),
            BtfType::Func(t) => t.type_info_size(),
            BtfType::Int(t) => t.type_info_size(),
            BtfType::Float(t) => t.type_info_size(),
            BtfType::Enum(t) => t.type_info_size(),
            BtfType::Array(t) => t.type_info_size(),
            BtfType::Struct(t) => t.type_info_size(),
            BtfType::Union(t) => t.type_info_size(),
            BtfType::FuncProto(t) => t.type_info_size(),
            BtfType::Var(t) => t.type_info_size(),
            BtfType::DataSec(t) => t.type_info_size(),
            BtfType::DeclTag(t) => t.type_info_size(),
            BtfType::TypeTag(t) => t.type_info_size(),
        }
    }

    pub(crate) fn name_offset(&self) -> u32 {
        match self {
            BtfType::Unknown => 0,
            BtfType::Fwd(t) => t.name_offset,
            BtfType::Const(t) => t.name_offset,
            BtfType::Volatile(t) => t.name_offset,
            BtfType::Restrict(t) => t.name_offset,
            BtfType::Ptr(t) => t.name_offset,
            BtfType::Typedef(t) => t.name_offset,
            BtfType::Func(t) => t.name_offset,
            BtfType::Int(t) => t.name_offset,
            BtfType::Float(t) => t.name_offset,
            BtfType::Enum(t) => t.name_offset,
            BtfType::Array(t) => t.name_offset,
            BtfType::Struct(t) => t.name_offset,
            BtfType::Union(t) => t.name_offset,
            BtfType::FuncProto(t) => t.name_offset,
            BtfType::Var(t) => t.name_offset,
            BtfType::DataSec(t) => t.name_offset,
            BtfType::DeclTag(t) => t.name_offset,
            BtfType::TypeTag(t) => t.name_offset,
        }
    }

    pub(crate) fn kind(&self) -> BtfKind {
        match self {
            BtfType::Unknown => BtfKind::Unknown,
            BtfType::Fwd(t) => t.kind(),
            BtfType::Const(t) => t.kind(),
            BtfType::Volatile(t) => t.kind(),
            BtfType::Restrict(t) => t.kind(),
            BtfType::Ptr(t) => t.kind(),
            BtfType::Typedef(t) => t.kind(),
            BtfType::Func(t) => t.kind(),
            BtfType::Int(t) => t.kind(),
            BtfType::Float(t) => t.kind(),
            BtfType::Enum(t) => t.kind(),
            BtfType::Array(t) => t.kind(),
            BtfType::Struct(t) => t.kind(),
            BtfType::Union(t) => t.kind(),
            BtfType::FuncProto(t) => t.kind(),
            BtfType::Var(t) => t.kind(),
            BtfType::DataSec(t) => t.kind(),
            BtfType::DeclTag(t) => t.kind(),
            BtfType::TypeTag(t) => t.kind(),
        }
    }

    pub(crate) fn is_composite(&self) -> bool {
        matches!(self, BtfType::Struct(_) | BtfType::Union(_))
    }

    pub(crate) fn members(&self) -> Option<impl Iterator<Item = &BtfMember>> {
        match self {
            BtfType::Struct(t) => Some(t.members.iter()),
            BtfType::Union(t) => Some(t.members.iter()),
            _ => None,
        }
    }

    pub(crate) fn member_bit_field_size(&self, member: &BtfMember) -> Option<usize> {
        match self {
            BtfType::Struct(t) => Some(t.member_bit_field_size(member)),
            BtfType::Union(t) => Some(t.member_bit_field_size(member)),
            _ => None,
        }
    }

    pub(crate) fn member_bit_offset(&self, member: &BtfMember) -> Option<usize> {
        match self {
            BtfType::Struct(t) => Some(t.member_bit_offset(member)),
            BtfType::Union(t) => Some(t.member_bit_offset(member)),
            _ => None,
        }
    }
}

fn type_kind(info: u32) -> Result<BtfKind, BtfError> {
    ((info >> 24) & 0x1F).try_into()
}

fn type_vlen(info: u32) -> usize {
    (info & 0xFFFF) as usize
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

    if local_ty.kind() != target_ty.kind() {
        return Ok(false);
    }

    for _ in 0..MAX_RESOLVE_DEPTH {
        local_id = local_btf.resolve_type(local_id)?;
        target_id = target_btf.resolve_type(target_id)?;
        let local_ty = local_btf.type_by_id(local_id)?;
        let target_ty = target_btf.type_by_id(target_id)?;

        if local_ty.kind() != target_ty.kind() {
            return Ok(false);
        }

        match local_ty {
            BtfType::Unknown
            | BtfType::Struct(_)
            | BtfType::Union(_)
            | BtfType::Enum(_)
            | BtfType::Fwd(_)
            | BtfType::Float(_) => return Ok(true),
            BtfType::Int(local) => {
                if let BtfType::Int(target) = target_ty {
                    return Ok(local.offset() == 0 && target.offset() == 0);
                }
            }
            BtfType::Ptr(local) => {
                if let BtfType::Ptr(target) = target_ty {
                    local_id = local.btf_type;
                    target_id = target.btf_type;
                    continue;
                }
            }
            BtfType::Array(Array { array: local, .. }) => {
                if let BtfType::Array(Array { array: target, .. }) = target_ty {
                    local_id = local.element_type;
                    target_id = target.element_type;
                    continue;
                }
            }
            BtfType::FuncProto(local) => {
                if let BtfType::FuncProto(target) = target_ty {
                    if local.params.len() != target.params.len() {
                        return Ok(false);
                    }

                    for (l_param, t_param) in local.params.iter().zip(target.params.iter()) {
                        let local_id = local_btf.resolve_type(l_param.btf_type)?;
                        let target_id = target_btf.resolve_type(t_param.btf_type)?;
                        if !types_are_compatible(local_btf, local_id, target_btf, target_id)? {
                            return Ok(false);
                        }
                    }

                    local_id = local.return_type;
                    target_id = target.return_type;
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

        if local_ty.kind() != target_ty.kind() {
            return Ok(false);
        }

        match local_ty {
            BtfType::Fwd(_) | BtfType::Enum(_) => {
                let flavorless_name =
                    |name: &str| name.split_once("___").map_or(name, |x| x.0).to_string();

                let local_name = flavorless_name(&local_btf.type_name(local_ty)?);
                let target_name = flavorless_name(&target_btf.type_name(target_ty)?);

                return Ok(local_name == target_name);
            }
            BtfType::Int(local) => {
                if let BtfType::Int(target) = target_ty {
                    return Ok(local.offset() == 0 && target.offset() == 0);
                }
            }
            BtfType::Float(_) => return Ok(true),
            BtfType::Ptr(_) => return Ok(true),
            BtfType::Array(Array { array: local, .. }) => {
                if let BtfType::Array(Array { array: target, .. }) = target_ty {
                    local_id = local.element_type;
                    target_id = target.element_type;
                    continue;
                }
            }
            _ => panic!("this shouldn't be reached"),
        }
    }

    Err(BtfError::MaximumTypeDepthReached { type_id: local_id })
}

fn bytes_of<T>(val: &T) -> &[u8] {
    // Safety: all btf types are POD
    unsafe { crate::util::bytes_of(val) }
}
#[cfg(test)]
mod tests {
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
            Ok(BtfType::Int(new)) => {
                assert_eq!(new.name_offset, 1);
                assert_eq!(new.size, 8);
                assert_eq!(new.bits(), 64);
                let data2 = new.to_bytes();
                assert_eq!(data, data2);
            }
            Ok(t) => panic!("expected int type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
    }

    #[test]
    fn test_write_btf_long_unsigned_int() {
        let data: &[u8] = &[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x00, 0x00,
        ];
        let int = Int::new(1, 8, IntEncoding::None, 0);
        assert_eq!(int.to_bytes(), data);
    }

    #[test]
    fn test_write_btf_uchar() {
        let data: &[u8] = &[
            0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x00, 0x00,
        ];
        let int = Int::new(0x13, 1, IntEncoding::None, 0);
        assert_eq!(int.to_bytes(), data);
    }

    #[test]
    fn test_write_btf_signed_short_int() {
        let data: &[u8] = &[
            0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x01,
        ];
        let int = Int::new(0x4a, 2, IntEncoding::Signed, 0);
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
        assert_eq!(data, data2)
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
            Ok(BtfType::Array(_)) => {}
            Ok(t) => panic!("expected array type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2)
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
            Ok(BtfType::Struct(_)) => {}
            Ok(t) => panic!("expected struct type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2)
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
            Ok(BtfType::Union(_)) => {}
            Ok(t) => panic!("expected union type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2)
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
            Ok(BtfType::Enum(_)) => {}
            Ok(t) => panic!("expected enum type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2)
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
        assert_eq!(data, data2)
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
        assert_eq!(data, data2)
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
        assert_eq!(data, data2)
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
        assert_eq!(data, data2)
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
        assert_eq!(data, data2)
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
        assert_eq!(data, data2)
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
            Ok(BtfType::FuncProto(_)) => {}
            Ok(t) => panic!("expected func_proto type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2)
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
            Ok(BtfType::Var(_)) => {}
            Ok(t) => panic!("expected var type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        };
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2)
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
            Ok(BtfType::DataSec(ty)) => {
                assert_eq!(0, ty.size);
                assert_eq!(11, ty.entries[0].btf_type);
                assert_eq!(0, ty.entries[0].offset);
                assert_eq!(4, ty.entries[0].size);
            }
            Ok(t) => panic!("expected datasec type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
        let data2 = got.unwrap().to_bytes();
        assert_eq!(data, data2)
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
        assert_eq!(data, data2)
    }

    #[test]
    fn test_write_btf_func_proto() {
        let params = vec![
            BtfParam {
                name_offset: 1,
                btf_type: 1,
            },
            BtfParam {
                name_offset: 3,
                btf_type: 1,
            },
        ];
        let func_proto = FuncProto::new(params, 2);
        let data = func_proto.to_bytes();
        let got = unsafe { BtfType::read(&data, Endianness::default()) };
        match got {
            Ok(BtfType::FuncProto(fp)) => {
                assert_eq!(fp.params.len(), 2);
            }
            Ok(t) => panic!("expected func proto type, got {:#?}", t),
            Err(_) => panic!("unexpected error"),
        }
    }

    #[test]
    fn test_types_are_compatible() {
        let mut btf = Btf::new();
        let name_offset = btf.add_string("u32".to_string());
        let u32t = btf.add_type(BtfType::Int(Int::new(name_offset, 4, IntEncoding::None, 0)));
        let name_offset = btf.add_string("u64".to_string());
        let u64t = btf.add_type(BtfType::Int(Int::new(name_offset, 8, IntEncoding::None, 0)));
        let name_offset = btf.add_string("widgets".to_string());
        let array_type = btf.add_type(BtfType::Array(Array::new(name_offset, u64t, u32t, 16)));

        assert!(types_are_compatible(&btf, u32t, &btf, u32t).unwrap());
        // int types are compatible if offsets match. size and encoding aren't compared
        assert!(types_are_compatible(&btf, u32t, &btf, u64t).unwrap());
        assert!(types_are_compatible(&btf, array_type, &btf, array_type).unwrap());
    }
}
