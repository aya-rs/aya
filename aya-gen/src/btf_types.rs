use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    str::from_utf8,
};

use thiserror::Error;

use crate::bindgen;

#[derive(Error, Debug)]
pub enum Error {
    #[error("error executing bpftool")]
    BpfTool(#[source] io::Error),

    #[error("{stderr}\nbpftool failed with exit code {code}")]
    BpfToolExit { code: i32, stderr: String },

    #[error("bindgen failed")]
    Bindgen,

    #[error("rustfmt failed")]
    Rustfmt(#[source] io::Error),

    #[error("error reading header file")]
    ReadHeaderFile,
}

pub enum InputFile {
    Btf(PathBuf),
    Header(PathBuf),
}

pub fn generate<T: AsRef<str>>(input_file: InputFile, types: &[T]) -> Result<String, Error> {
    let mut bindgen = bindgen::bpf_builder();

    match input_file {
        InputFile::Btf(path) => {
            let c_header = c_header_from_btf(&path)?;
            bindgen = bindgen.header_contents("kernel_types.h", &c_header);
        }
        InputFile::Header(header) => {
            let c_header = fs::read_to_string(&header).map_err(|_| Error::ReadHeaderFile)?;
            let name = Path::new(&header).file_name().unwrap().to_str().unwrap();
            bindgen = bindgen.header_contents(name, &c_header);
        }
    }

    for ty in types {
        bindgen = bindgen.allowlist_type(ty);
    }

    let bindings = bindgen.generate().or(Err(Error::Bindgen))?.to_string();

    Ok(bindings)
}

fn c_header_from_btf(path: &Path) -> Result<String, Error> {
    let output = Command::new("bpftool")
        .args(&["btf", "dump", "file"])
        .arg(path)
        .args(&["format", "c"])
        .output()
        .map_err(Error::BpfTool)?;

    if !output.status.success() {
        return Err(Error::BpfToolExit {
            code: output.status.code().unwrap(),
            stderr: from_utf8(&output.stderr).unwrap().to_owned(),
        });
    }

    Ok(from_utf8(&output.stdout).unwrap().to_owned())
}
