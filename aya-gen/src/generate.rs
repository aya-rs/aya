use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    str,
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
    ReadHeaderFile(#[source] io::Error),
}

pub enum InputFile {
    Btf(PathBuf),
    Header(PathBuf),
}

pub fn generate<T: AsRef<str>>(
    input_file: InputFile,
    types: &[T],
    additional_flags: &[T],
) -> Result<String, Error> {
    let mut bindgen = bindgen::bpf_builder();

    let (c_header, name) = match &input_file {
        InputFile::Btf(path) => (c_header_from_btf(path)?, "kernel_types.h"),
        InputFile::Header(header) => (
            fs::read_to_string(&header).map_err(Error::ReadHeaderFile)?,
            header.file_name().unwrap().to_str().unwrap(),
        ),
    };

    for ty in types {
        bindgen = bindgen.allowlist_type(ty);
    }

    let dir = tempdir().unwrap();
    let file_path = dir.path().join(name);
    let mut file = File::create(&file_path).unwrap();
    let _ = file.write(c_header.as_bytes()).unwrap();

    let flags = combine_flags(
        &bindgen.command_line_flags(),
        &additional_flags
            .iter()
            .map(|s| s.as_ref().into())
            .collect::<Vec<_>>(),
    );

    let output = Command::new("bindgen")
        .arg(file_path)
        .args(&flags)
        .output()
        .map_err(Error::Bindgen)?;

    if !output.status.success() {
        return Err(Error::BindgenExit {
            code: output.status.code().unwrap(),
            stderr: str::from_utf8(&output.stderr).unwrap().to_owned(),
        });
    }

    Ok(str::from_utf8(&output.stdout).unwrap().to_owned())
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
            stderr: str::from_utf8(&output.stderr).unwrap().to_owned(),
        });
    }

    Ok(str::from_utf8(&output.stdout).unwrap().to_owned())
}

fn combine_flags(s1: &[String], s2: &[String]) -> Vec<String> {
    let mut args = Vec::new();
    let mut extra = Vec::new();

    for s in [s1, s2] {
        let mut s = s.splitn(2, |el| el == "--");
        // append args
        args.extend(s.next().unwrap().iter().cloned());
        if let Some(e) = s.next() {
            // append extra args
            extra.extend(e.iter().cloned());
        }
    }

    // append extra args
    if !extra.is_empty() {
        args.push("--".to_string());
        args.extend(extra);
    }

    args
}

#[cfg(test)]
mod test {
    use super::combine_flags;

    fn to_vec(s: &str) -> Vec<String> {
        s.split(" ").map(|x| x.into()).collect()
    }

    #[test]
    fn combine_arguments_test() {
        assert_eq!(
            combine_flags(&to_vec("a b"), &to_vec("c d"),).join(" "),
            "a b c d".to_string(),
        );

        assert_eq!(
            combine_flags(&to_vec("a -- b"), &to_vec("a b"),).join(" "),
            "a a b -- b".to_string(),
        );

        assert_eq!(
            combine_flags(&to_vec("a -- b"), &to_vec("c d"),).join(" "),
            "a c d -- b".to_string(),
        );

        assert_eq!(
            combine_flags(&to_vec("a b"), &to_vec("c -- d"),).join(" "),
            "a b c -- d".to_string(),
        );

        assert_eq!(
            combine_flags(&to_vec("a -- b"), &to_vec("c -- d"),).join(" "),
            "a c -- b d".to_string(),
        );

        assert_eq!(
            combine_flags(&to_vec("a -- b"), &to_vec("-- c d"),).join(" "),
            "a -- b c d".to_string(),
        );
    }
}
