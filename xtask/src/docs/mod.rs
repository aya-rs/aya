use std::{
    fs::File,
    io::BufRead,
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

    let mut search_indexes = read_lines("./target/doc/search-index.js")?
        .map(|l| l.unwrap())
        .collect::<Vec<_>>();
    search_indexes.truncate(search_indexes.len() - 2);
    let mut last = search_indexes.pop().unwrap();
    last = last.trim_end_matches('\\').to_string() + ",\\";
    search_indexes.push(last);

    for l in read_lines("./bpf/target/doc/search-index.js")?.skip(1) {
        search_indexes.push(l.unwrap());
    }
    let mut file = fs::File::options()
        .read(true)
        .write(true)
        .open("./target/doc/search-index.js")?;
    file.write_all(search_indexes.join("\n").as_bytes())?;

    Ok(())
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
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
