#![no_main]
use aya::{Btf, Endianness};
use libfuzzer_sys::fuzz_target;
use std::{env::temp_dir, fs::File, io::Write};

fuzz_target!(|data: &[u8]| {
    let mut path = temp_dir();
    path.push("btf");
    let mut file = File::create(&path).unwrap();
    file.write_all(data).unwrap();
    file.flush().unwrap();
    let _ = Btf::parse_file(path, Endianness::default());
});
