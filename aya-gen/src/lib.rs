use std::{
    fs::{create_dir_all, File},
    io::{self, Write},
    path::Path,
};

pub mod bindgen;
pub mod btf_types;
pub mod getters;
pub mod rustfmt;

pub fn write_to_file<T: AsRef<Path>>(path: T, code: &str) -> Result<(), io::Error> {
    if let Some(parent) = path.as_ref().parent() {
        create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    file.write_all(code.as_bytes())
}

pub fn write_to_file_fmt<T: AsRef<Path>>(path: T, code: &str) -> Result<(), io::Error> {
    if let Some(parent) = path.as_ref().parent() {
        create_dir_all(parent)?;
    }
    write_to_file(path, &rustfmt::format(code)?)
}
