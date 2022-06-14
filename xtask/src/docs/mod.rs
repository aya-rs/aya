use std::{
    path::{Path, PathBuf},
    process::Command,
};

use std::{fs, io, io::Write};

use indoc::indoc;

pub fn docs() -> Result<(), anyhow::Error> {
    let mut working_dir = PathBuf::from(".");

    let replace = Command::new("sed")
        .current_dir(&working_dir)
        .args(vec![
            "-i.bak",
            "s/crabby.svg/crabby_dev.svg/",
            "aya/src/lib.rs",
        ])
        .status()
        .expect("failed to replace logo");
    assert!(replace.success());

    let mut header_path = PathBuf::from(".");
    header_path.push("header.html");
    let mut header = fs::File::create(&header_path).expect("can't create header.html");
    header
        .write_all(r#"<meta name="robots" content="noindex">"#.as_bytes())
        .expect("can't write header.html contents");
    header.flush().expect("couldn't flush contents");

    let abs_header_path = fs::canonicalize(&header_path).unwrap();
    let args = vec![
        "+nightly",
        "doc",
        "--workspace",
        "--no-deps",
        "--all-features",
    ];

    let status = Command::new("cargo")
        .current_dir(&working_dir)
        .env(
            "RUSTDOCFLAGS",
            format!("--html-in-header {}", abs_header_path.to_str().unwrap()),
        )
        .args(&args)
        .status()
        .expect("failed to build aya docs");
    assert!(status.success());

    working_dir.push("bpf");

    let replace = Command::new("sed")
        .current_dir(&working_dir)
        .args(vec![
            "-i.bak",
            "s/crabby.svg/crabby_dev.svg/",
            "aya-bpf/src/lib.rs",
        ])
        .status()
        .expect("failed to replace logo");
    assert!(replace.success());

    let status = Command::new("cargo")
        .current_dir(&working_dir)
        .env(
            "RUSTDOCFLAGS",
            format!("--html-in-header {}", abs_header_path.to_str().unwrap()),
        )
        .args(&args)
        .status()
        .expect("failed to build aya-bpf docs");
    assert!(status.success());

    copy_dir_all("./target/doc", "site/user")?;
    copy_dir_all("./bpf/target/doc", "site/bpf")?;

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

    fs::rename("aya/src/lib.rs.bak", "aya/src/lib.rs").unwrap();
    fs::rename("bpf/aya-bpf/src/lib.rs.bak", "bpf/aya-bpf/src/lib.rs").unwrap();

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
