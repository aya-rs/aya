use anyhow::{anyhow, Context as _, Result};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

use std::{fs, io, io::Write};

use indoc::indoc;

pub fn exec(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to run {cmd:?}"))?;
    match status.code() {
        Some(code) => match code {
            0 => Ok(()),
            code => Err(anyhow!("{cmd:?} exited with code {code}")),
        },
        None => Err(anyhow!("{cmd:?} terminated by signal")),
    }
}

pub fn docs() -> Result<()> {
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
    copy_dir_all("./target/doc".as_ref(), "./site/user".as_ref())?;
    copy_dir_all(
        "./target/bpfel-unknown-none/doc".as_ref(),
        "./site/bpf".as_ref(),
    )?;

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

fn build_docs(working_dir: &Path, abs_header_path: &Path) -> Result<()> {
    exec(Command::new("sed").current_dir(working_dir).args([
        "-i.bak",
        "s/crabby.svg/crabby_dev.svg/",
        "src/lib.rs",
    ]))?;

    exec(
        Command::new("cargo")
            .current_dir(working_dir)
            .env(
                "RUSTDOCFLAGS",
                format!(
                    "--cfg docsrs --html-in-header {} -D warnings",
                    abs_header_path.to_str().unwrap()
                ),
            )
            .args(["+nightly", "doc", "--no-deps", "--all-features"]),
    )?;

    fs::rename(
        working_dir.join("src/lib.rs.bak"),
        working_dir.join("src/lib.rs"),
    )
    .context("Failed to rename lib.rs.bak to lib.rs")
}

fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src = entry.path();
        let src = src.as_path();
        let dst = dst.join(entry.file_name());
        let dst = dst.as_path();
        if ty.is_dir() {
            copy_dir_all(src, dst)?;
        } else if !dst.exists() {
            fs::copy(src, dst)?;
        }
    }
    Ok(())
}
