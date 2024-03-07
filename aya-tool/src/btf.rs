use aya_obj::btf::{Btf, BtfType, IntEncoding, VarLinkage};
use object::Endianness;

use std::{fmt::Write, path::Path};

pub fn print_btf<P: AsRef<Path>>(path: P) -> anyhow::Result<()> {
    let btf = Btf::parse_elf_file(path, Endianness::default())?;
    for (i, t) in btf.types().enumerate().skip(1) {
        let kind = t.kind();
        let name = if t.name_offset() > 0 {
            format!(
                "'{}'",
                btf.string_at(t.name_offset())
                    .unwrap_or(std::borrow::Cow::Borrowed(""))
            )
        } else {
            "''".to_owned()
        };
        let info = match t {
            BtfType::Unknown => "".to_string(),
            BtfType::Fwd(_) => "type_id=0".to_string(),
            BtfType::Const(ty) => format!("type_id={}", ty.btf_type()),
            BtfType::Volatile(ty) => format!("type_id={}", ty.btf_type()),
            BtfType::Restrict(ty) => format!("type_id={}", ty.btf_type()),
            BtfType::Ptr(ty) => format!("type_id={}", ty.btf_type()),
            BtfType::Typedef(ty) => format!("type_id={}", ty.btf_type()),
            BtfType::Func(ty) => format!("type_id={}", ty.btf_type()),
            BtfType::Int(i) => {
                let encoding = match i.encoding() {
                    IntEncoding::Signed => "(signed)",
                    IntEncoding::Char => "(char)",
                    IntEncoding::Bool => "(bool)",
                    IntEncoding::None => "(none)",
                    IntEncoding::Unknown => "(unknown)",
                };
                format!(
                    "size={} bits_offset={} nr_bits={} encoding={}",
                    i.size(),
                    i.offset(),
                    i.bits(),
                    encoding,
                )
            }
            BtfType::Float(_) => todo!(),
            BtfType::Enum(_) => todo!(),
            BtfType::Array(ty) => {
                format!(
                    "type_id=0 index_type_id={} nr_elems={}",
                    ty.index_type(),
                    ty.len()
                )
            }
            BtfType::Struct(ty) => {
                let size = ty.size();
                let vlen = ty.vlen();
                let mut out = format!("size={} vlen={}", size, vlen,);
                for m in ty.members() {
                    let name = btf
                        .string_at(m.name_offset())
                        .unwrap_or(std::borrow::Cow::Borrowed(""));
                    let type_id = m.btf_type();
                    let offset = ty.member_bit_offset(m);
                    write!(out, "\n\t'{name}' type_id={type_id} bits_offset={offset}")?;
                }
                out
            }
            BtfType::Union(_) => todo!(),
            BtfType::FuncProto(ty) => {
                let ret_type_id = ty.return_type();
                let vlen = ty.vlen();
                let mut out = format!("ret_type_id={ret_type_id} vlen={vlen}");
                for p in ty.params() {
                    let name = btf
                        .string_at(p.name_offset())
                        .unwrap_or(std::borrow::Cow::Borrowed(""));
                    let type_id = p.btf_type();
                    write!(out, "\n\t'{name}' type_id={type_id}")?;
                }
                out
            }
            BtfType::Var(ty) => {
                let type_id = ty.btf_type();
                let linkage = match ty.linkage() {
                    VarLinkage::Static => "static".to_owned(),
                    VarLinkage::Global => "global".to_owned(),
                    VarLinkage::Extern => "extern".to_owned(),
                    VarLinkage::Unknown => "unknown".to_owned(),
                };
                format!("type_id={type_id} linkage={linkage}")
            }
            BtfType::DataSec(ty) => {
                let size = ty.size();
                let vlen = ty.vlen();
                let mut out = format!("size={size} vlen={vlen}");
                for entry in ty.entries() {
                    let points_to = btf.type_by_id(entry.btf_type()).unwrap();
                    let name = btf
                        .string_at(points_to.name_offset())
                        .unwrap_or(std::borrow::Cow::Borrowed(""));
                    write!(
                        out,
                        "\n\ttype_id={} offset={} size={} ({} '{}')",
                        entry.btf_type(),
                        entry.offset(),
                        entry.size(),
                        points_to.kind(),
                        name
                    )?;
                }
                out
            }
            BtfType::DeclTag(_) => unimplemented!("decl tag formatting not implemented"),
            BtfType::TypeTag(_) => unimplemented!("type tag formatting not implemented"),
            BtfType::Enum64(_) => unimplemented!("enum64 formatting not implemented"),
        };
        println!("[{i}] {kind} {name} {info}");
    }
    Ok(())
}
