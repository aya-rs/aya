use std::{
    fs::File,
    io::{self, Write},
    path::Path,
};

pub mod bindgen;
pub mod generate;
pub mod rustfmt;

pub fn write_to_file<T: AsRef<Path>>(path: T, code: &str) -> Result<(), io::Error> {
    let mut file = File::create(path)?;
    file.write_all(code.as_bytes())
}

pub fn write_to_file_fmt<T: AsRef<Path>>(path: T, code: &str) -> Result<(), io::Error> {
    write_to_file(path, &rustfmt::format(code)?)
}
