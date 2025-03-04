use std::{
    fs::{create_dir_all, File},
    io::{self, Write},
    path::Path,
};

pub mod bindgen;
pub mod btf;
pub mod generate;
pub mod rustfmt;

pub use generate::{generate, InputFile};

pub fn write_to_file<T: AsRef<Path>>(path: T, code: &str) -> Result<(), io::Error> {
    // Create parent directories if they don't exist already
    if let Some(parent) = path.as_ref().parent() {
        if !parent.exists() {
            create_dir_all(parent)?;
        }
    }

    let mut file = File::create(path)?;
    file.write_all(code.as_bytes())
}

pub fn write_to_file_fmt<T: AsRef<Path>>(path: T, code: &str) -> Result<(), io::Error> {
    write_to_file(path, &rustfmt::format(code)?)
}
