use std::{ffi::OsString, fs, io::Write as _, process::Command};

use anyhow::{Context as _, Result};
use cargo_metadata::Metadata;
use indoc::{indoc, writedoc};
use xtask::exec;

pub fn docs(metadata: Metadata) -> Result<()> {
    const PACKAGE_TO_DESCRIPTION: &[(&str, &str)] = &[
        ("aya", "User-space BPF program loading and manipulation"),
        ("aya-bpf", "Kernel-space BPF program implementation toolkit"),
        ("aya-log-ebpf", "Kernel-space logging from BPF programs"),
        (
            "aya-log",
            "User-space consumption of logs from BPF programs",
        ),
    ];

    let Metadata {
        workspace_root,
        target_directory,
        ..
    } = metadata;

    exec(
        Command::new("cargo")
            .current_dir(&workspace_root)
            .args(["clean", "--doc"]),
    )?;

    let tmp = tempfile::tempdir().context("create tempdir")?;
    let header = tmp.path().join("header.html");
    fs::write(&header, r#"<meta name="robots" content="noindex">"#).context("write header.html")?;

    let mut rustdocflags = OsString::new();
    rustdocflags.push("--cfg docsrs --html-in-header ");
    rustdocflags.push(header);
    rustdocflags.push(" -D warnings");

    exec(
        Command::new("cargo")
            .current_dir(&workspace_root)
            .env("RUSTDOCFLAGS", rustdocflags)
            .args(["+nightly", "doc", "--no-deps", "--all-features"])
            .args(
                PACKAGE_TO_DESCRIPTION
                    .iter()
                    .flat_map(|(package, _)| ["--package", package]),
            ),
    )?;

    let site = workspace_root.join("site");
    match fs::remove_dir_all(&site) {
        Ok(()) => {}
        Err(err) => {
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(err).context(format!("remove {site:?}"));
            }
        }
    }
    let doc = target_directory.join("doc");
    fs::rename(&doc, &site).with_context(|| format!("rename {doc:?} to {site:?}"))?;

    exec(Command::new("sh").current_dir(&site).args([
        "-c",
        "grep -FRl crabby.svg | xargs sed -i s/crabby.svg/crabby_dev.svg/g",
    ]))?;

    fs::write(
        site.join("robots.txt"),
        indoc! {r"
    User-Agent:*
    Disallow: /
    "},
    )
    .context("can't write robots.txt")?;

    let mut index = fs::File::create(site.join("index.html"))
        .with_context(|| format!("create {site:?}/index.html"))?;
    writedoc! {&mut index, r#"
        <html>
            <meta name="robots" content="noindex">
            <body>
              <ul>
    "#}
    .context("write to index.html")?;

    for (package, description) in PACKAGE_TO_DESCRIPTION {
        let package = package.replace('-', "_");
        writedoc! {&mut index, r#"
            <li><a href="{package}/index.html">Aya {description}</a></li>
        "#}
        .context("write to string")?;
    }

    writedoc! {&mut index, r#"
              </ul>
            </body>
        </html>
    "#}
    .context("write to index.html")?;

    Ok(())
}
