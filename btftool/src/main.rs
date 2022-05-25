use aya::{
    btf::{member_bit_offset, type_vlen, BtfKind, BtfType},
    Btf, BtfError, Endianness,
};
use clap::{Parser, Subcommand};
use object::{Object, ObjectSection};
use std::{
    fmt::{self, Write},
    fs, io,
    path::Path,
};
use thiserror::Error;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Dumps the .BTF ELF Section
    Dump { file: Option<String> },
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(".BTF section not found")]
    NoBTF,
    #[error("error parsing ELF data")]
    ElfError(#[from] object::read::Error),
    #[error(transparent)]
    IOError(io::Error),
    #[error(transparent)]
    FmtError(fmt::Error),
    #[error(transparent)]
    BtfError(BtfError),
}

fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Dump { file } => {
            dump(file.as_ref().unwrap())?;
        }
    }
    Ok(())
}

fn dump<P: AsRef<Path>>(input: P) -> Result<(), Error> {
    let bin_data = fs::read(input).map_err(Error::IOError)?;
    let obj_file = object::File::parse(&*bin_data).map_err(Error::ElfError)?;
    if let Some(section) = obj_file.section_by_name(".BTF") {
        let btf = Btf::parse(section.data()?, Endianness::default()).map_err(Error::BtfError)?;
        for (i, t) in btf.types().enumerate().skip(1) {
            let kind = t.kind().unwrap_or(None).unwrap_or(BtfKind::Unknown);
            let name = if let Some(offset) = t.name_offset() {
                if offset > 0 {
                    format!(
                        "'{}'",
                        btf.string_at(offset)
                            .unwrap_or(std::borrow::Cow::Borrowed(""))
                    )
                } else {
                    "''".to_owned()
                }
            } else {
                "''".to_owned()
            };
            let info = match t {
                BtfType::Unknown => "".to_string(),
                BtfType::Fwd(t)
                | BtfType::Const(t)
                | BtfType::Volatile(t)
                | BtfType::Restrict(t)
                | BtfType::Ptr(t)
                | BtfType::Typedef(t)
                | BtfType::Func(t) => {
                    format!("type_id={}", unsafe { t.__bindgen_anon_1.type_ })
                }
                BtfType::Int(t, size) => {
                    let encoding = match (t.info & 0x0f000000) >> 24 {
                        1 => "(signed)",
                        2 => "(char)",
                        4 => "(bool)",
                        _ => "(none)",
                    };
                    let offset = (t.info & 0x00ff0000) >> 16;
                    let bits = t.info & 0x000000ff;
                    format!(
                        "size={} bits_offset={} nr_bits={} encoding={}",
                        size, offset, bits, encoding,
                    )
                }
                BtfType::Float(_) => todo!(),
                BtfType::Enum(_, _) => todo!(),
                BtfType::Array(_, array) => {
                    format!(
                        "type_id={} index_type_id={} nr_elems={}",
                        array.type_, array.index_type, array.nelems
                    )
                }
                BtfType::Struct(ty, members) => {
                    let size = unsafe { ty.__bindgen_anon_1.size };
                    let vlen = type_vlen(ty);
                    let mut out = format!("size={} vlen={}", size, vlen,);
                    for m in members {
                        let name = btf
                            .string_at(m.name_off)
                            .unwrap_or(std::borrow::Cow::Borrowed(""));
                        let type_id = m.type_;
                        let offset = member_bit_offset(ty.info, m);
                        write!(out, "\n\t'{name}' type_id={type_id} bits_offset={offset}")
                            .map_err(Error::FmtError)?;
                    }
                    out
                }
                BtfType::Union(_, _) => todo!(),
                BtfType::FuncProto(ty, params) => {
                    let ret_type_id = unsafe { ty.__bindgen_anon_1.type_ };
                    let vlen = type_vlen(ty);
                    let mut out = format!("ret_type_id={ret_type_id} vlen={vlen}");
                    for p in params {
                        let name = btf
                            .string_at(p.name_off)
                            .unwrap_or(std::borrow::Cow::Borrowed(""));
                        let type_id = p.type_;
                        write!(out, "\n\t'{name}' type_id={type_id}").map_err(Error::FmtError)?;
                    }
                    out
                }
                BtfType::Var(ty, var) => {
                    let type_id = unsafe { ty.__bindgen_anon_1.type_ };
                    let linkage = match var.linkage {
                        0 => "static".to_owned(),
                        1 => "global".to_owned(),
                        other => format!("{other}"),
                    };
                    format!("type_id={type_id} linkage={linkage}")
                }
                BtfType::DataSec(ty, secinfo) => {
                    let size = unsafe { ty.__bindgen_anon_1.size };
                    let vlen = type_vlen(ty);
                    let mut out = format!("size={size} vlen={vlen}");
                    for s in secinfo {
                        let points_to = btf.type_by_id(s.type_).unwrap();
                        let name = btf
                            .string_at(points_to.name_offset().unwrap_or(0))
                            .unwrap_or(std::borrow::Cow::Borrowed(""));
                        write!(
                            out,
                            "\n\ttype_id={} offset={} size={} ({} '{}')",
                            s.type_,
                            s.offset,
                            s.size,
                            points_to.kind().unwrap_or(None).unwrap_or(BtfKind::Unknown),
                            name
                        )
                        .map_err(Error::FmtError)?;
                    }
                    out
                }
                BtfType::DeclTag(_, _) => unimplemented!("decl tag formatting not implemented"),
                BtfType::TypeTag(_) => unimplemented!("type tag formatting not implemented"),
            };
            println!("[{i}] {kind} {name} {info}");
        }
        Ok(())
    } else {
        Err(Error::NoBTF)
    }
}
