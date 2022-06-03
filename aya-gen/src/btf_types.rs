use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    str::from_utf8,
};

use tempfile::tempdir;

use thiserror::Error;

use crate::bindgen;

#[derive(Error, Debug)]
pub enum Error {
    #[error("error executing bpftool")]
    BpfTool(#[source] io::Error),

    #[error("{stderr}\nbpftool failed with exit code {code}")]
    BpfToolExit { code: i32, stderr: String },

    #[error("bindgen failed")]
    Bindgen(#[source] io::Error),

    #[error("{stderr}\nbindgen failed with exit code {code}")]
    BindgenExit { code: i32, stderr: String },

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

    let (c_header, name) = match input_file {
        InputFile::Btf(path) => (c_header_from_btf(&path)?, "kernel_types.h".to_string()),
        InputFile::Header(header) => (
            fs::read_to_string(&header).map_err(|_| Error::ReadHeaderFile)?,
            header.file_name().unwrap().to_str().unwrap().to_owned(),
        ),
    };

    for ty in types {
        bindgen = bindgen.allowlist_type(ty);
    }

    // TODO: check if this part should be moved to bindgen::generate()
    let dir = tempdir().unwrap();
    let file_path = dir.path().join(name);
    let mut file = File::create(&file_path).unwrap();
    let _ = file.write(c_header.as_bytes()).unwrap();

    let flags = bindgen.command_line_flags();

    // TODO: check proper logging; it seems useful to see what command is
    // launched but we can't disturb the normal output of the aya-gen tool
    println!(
        "Launching bindgen {} {}",
        file_path.to_str().unwrap(),
        flags.join(" ")
    );

    let output = Command::new("bindgen")
        .arg(file_path)
        .args(flags)
        // TODO: pass additional arguments after --
        .output()
        .map_err(Error::Bindgen)?;

    if !output.status.success() {
        return Err(Error::BindgenExit {
            code: output.status.code().unwrap(),
            stderr: from_utf8(&output.stderr).unwrap().to_owned(),
        });
    }

    Ok(from_utf8(&output.stdout).unwrap().to_owned())
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
