use std::{
    path::{Path, PathBuf},
    process::Command,
};

use std::{fs, io, io::Write};

use indoc::indoc;

pub fn docs() -> Result<(), anyhow::Error> {
    let current_dir = PathBuf::from(".");
    let header_path = current_dir.join("header.html");
    let mut header = fs::File::create(&header_path).expect("can't create header.html");
    header
        .write_all(r#"<meta name="robots" content="noindex">"#.as_bytes())
        .expect("can't write header.html contents");
    header.flush().expect("couldn't flush contents");
    let abs_header_path = fs::canonicalize(&header_path).unwrap();

    build_docs(&current_dir.join("aya"), &abs_header_path)?;
    build_docs(&current_dir.join("bpf/aya-bpf"), &abs_header_path)?;
    copy_dir_all("./target/doc", "./site/user")?;
    copy_dir_all("./target/bpfel-unknown-none/doc", "./site/bpf")?;

    let mut robots = fs::File::create("site/robots.txt").expect("can't create robots.txt");
    robots
        .write_all(
            indoc! {r#"
    User-Agent:*
    Disallow: /
    "#}
            .as_bytes(),
        )
        .expect("can't write robots.txt");

    let mut index = fs::File::create("site/index.html").expect("can't create index.html");
    index
        .write_all(
            indoc! {r#"
        <html>
            <meta name="robots" content="noindex">
            <body>
              <ul>
                <li><a href="user/aya/index.html">Aya User-space Development Documentation</a></li>
                <li><a href="bpf/aya_bpf/index.html">Aya Kernel-space Development Documentation</a></li>
              </ul>
            </body>
        </html>
    "#}
            .as_bytes(),
        )
        .expect("can't write index.html");
    Ok(())
}

fn build_docs(working_dir: &PathBuf, abs_header_path: &Path) -> Result<(), anyhow::Error> {
    let replace = Command::new("sed")
        .current_dir(working_dir)
        .args(vec!["-i.bak", "s/crabby.svg/crabby_dev.svg/", "src/lib.rs"])
        .status()
        .expect("failed to replace logo");
    assert!(replace.success());

    let args = vec!["+nightly", "doc", "--no-deps", "--all-features"];

    let status = Command::new("cargo")
        .current_dir(working_dir)
        .env(
            "RUSTDOCFLAGS",
            format!(
                "--cfg docsrs --html-in-header {} -D warnings",
                abs_header_path.to_str().unwrap()
            ),
        )
        .args(&args)
        .status()
        .expect("failed to build aya docs");
    assert!(status.success());
    fs::rename(
        working_dir.join("src/lib.rs.bak"),
        working_dir.join("src/lib.rs"),
    )
    .unwrap();
    Ok(())
}

fn copy_dir_all<P1: AsRef<Path>, P2: AsRef<Path>>(src: P1, dst: P2) -> io::Result<()> {
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
