use std::{
    fmt::Write as _,
    fs::{read_to_string, File},
    io::Write as _,
    path::Path,
};

use anyhow::{bail, Context as _, Result};
use cargo_metadata::{Metadata, Package};
use clap::Parser;
use dialoguer::{theme::ColorfulTheme, Confirm};
use diff::{lines, Result as Diff};

#[derive(Debug, Parser)]
pub struct Options {
    /// Bless new API changes.
    #[clap(long)]
    pub bless: bool,
}

pub fn public_api(options: Options, metadata: Metadata) -> Result<()> {
    let toolchain = "nightly";
    let Options { bless } = options;

    if !rustup_toolchain::is_installed(toolchain)? {
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("No nightly toolchain detected. Would you like to install one?")
            .interact()?
        {
            rustup_toolchain::install(toolchain)?;
        } else {
            bail!("nightly toolchain not installed")
        }
    }

    let Metadata {
        workspace_root,
        packages,
        ..
    } = &metadata;

    let errors = packages
        .iter()
        .fold(String::new(), |mut buf, Package { name, publish, .. }| {
            if !matches!(publish, Some(publish) if publish.is_empty()) {
                match check_package_api(name, toolchain, bless, workspace_root.as_std_path()) {
                    Ok(diff) => {
                        if !diff.is_empty() {
                            writeln!(
                                &mut buf,
                                "{name} public API changed; re-run with --bless: {diff}"
                            )
                            .unwrap();
                        }
                    }
                    Err(err) => {
                        writeln!(&mut buf, "{name} failed to check public API: {err}").unwrap();
                    }
                }
            }
            buf
        });

    if !errors.is_empty() {
        bail!("{errors}");
    }
    Ok(())
}

fn check_package_api(
    package: &str,
    toolchain: &str,
    bless: bool,
    workspace_root: &Path,
) -> Result<String> {
    let path = workspace_root
        .join("xtask")
        .join("public-api")
        .join(package)
        .with_extension("txt");

    let rustdoc_json = rustdoc_json::Builder::default()
        .toolchain(toolchain)
        .package(package)
        .all_features(true)
        .build()
        .context("rustdoc_json::Builder::build")?;

    let public_api = public_api::Builder::from_rustdoc_json(rustdoc_json)
        .build()
        .context("public_api::Builder::build")?;

    if bless {
        let mut output =
            File::create(&path).with_context(|| format!("error creating {}", path.display()))?;
        write!(&mut output, "{}", public_api)
            .with_context(|| format!("error writing {}", path.display()))?;
    }
    let current_api =
        read_to_string(&path).with_context(|| format!("error reading {}", path.display()))?;

    Ok(lines(&current_api, &public_api.to_string())
        .into_iter()
        .fold(String::new(), |mut buf, diff| {
            match diff {
                Diff::Both(..) => (),
                Diff::Right(line) => writeln!(&mut buf, "-{}", line).unwrap(),
                Diff::Left(line) => writeln!(&mut buf, "+{}", line).unwrap(),
            };
            buf
        }))
}
