use std::{
    path::{Path, PathBuf},
    process::Command,
};

use std::{fs, io, io::Write};

pub fn docs() -> Result<(), anyhow::Error> {
    let mut working_dir = PathBuf::from(".");

    let args = vec![
        "+nightly",
        "doc",
        "--workspace",
        "--no-deps",
        "--all-features",
    ];

    let status = Command::new("cargo")
        .current_dir(&working_dir)
        .args(&args)
        .status()
        .expect("failed to build aya docs");
    assert!(status.success());

    working_dir.push("bpf");
    let status = Command::new("cargo")
        .current_dir(&working_dir)
        .args(&args)
        .status()
        .expect("failed to build aya-bpf docs");
    assert!(status.success());

    copy_dir_all("./bpf/target/doc", "./target/doc")?;

    let crates_js = b"window.ALL_CRATES = [\"aya\", \"aya_bpf\", \"aya_bpf_bindings\", \"aya_bpf_cty\", \"aya_bpf_macros\", \"aya_gen\"];\n";
    let mut file = fs::File::options()
        .read(true)
        .write(true)
        .open("./target/doc/crates.js")?;
    file.write_all(crates_js)?;

    Ok(())
}

fn copy_dir_all<P: AsRef<Path>>(src: P, dst: P) -> io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            let new_path = dst.as_ref().join(entry.file_name());
            if !new_path.exists() {
                fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
            }
        }
    }
    Ok(())
}
