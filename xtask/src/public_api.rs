use std::{
    fmt::Write as _,
    fs::{read_to_string, write},
    path::Path,
};

use anyhow::{bail, Context as _};
use cargo_metadata::{Metadata, Package};
use clap::Parser;
use dialoguer::{theme::ColorfulTheme, Confirm};
use diff::{lines, Result as Diff};
use thiserror::Error;

#[derive(Debug, Parser)]
pub struct Options {
    /// Bless new API changes.
    #[clap(long)]
    pub bless: bool,
}

#[derive(Error, Debug)]
enum PublicApiError {
    #[error("error checking public api for {package}\n{source}\n")]
    Error {
        package: String,
        source: anyhow::Error,
    },
    #[error("public api for {package} changed:\n{diff}\n")]
    Changed { package: String, diff: String },
}

pub fn public_api(options: Options, metadata: Metadata) -> anyhow::Result<()> {
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

    let mut buf = String::new();
    packages.iter().for_each(|Package { name, publish, .. }| {
        if matches!(publish, Some(publish) if publish.is_empty()) {
            return;
        }
        if let Err(e) = check_package_api(name, toolchain, bless, workspace_root.as_std_path()) {
            write!(&mut buf, "{}", e).unwrap();
        }
    });

    if !buf.is_empty() {
        bail!("public api may have changed in one or more packages.\nplease bless by re-running this command with --bless\nErrors:\n{buf}");
    }
    Ok(())
}

fn check_package_api(
    package: &str,
    toolchain: &str,
    bless: bool,
    workspace_root: &Path,
) -> Result<(), PublicApiError> {
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
        .map_err(|source| PublicApiError::Error {
            package: package.to_string(),
            source: source.into(),
        })?;

    let public_api = public_api::Builder::from_rustdoc_json(rustdoc_json)
        .build()
        .map_err(|source| PublicApiError::Error {
            package: package.to_string(),
            source: source.into(),
        })?;

    if bless {
        write(&path, public_api.to_string().as_bytes()).map_err(|source| {
            PublicApiError::Error {
                package: package.to_string(),
                source: source.into(),
            }
        })?;
    }
    let current_api = read_to_string(&path)
        .with_context(|| format!("error reading {}", &path.display()))
        .map_err(|source| PublicApiError::Error {
            package: package.to_string(),
            source,
        })?;

    let mut buf = String::new();
    lines(&current_api, &public_api.to_string())
        .into_iter()
        .for_each(|diff| match diff {
            Diff::Both(..) => (),
            Diff::Right(line) => writeln!(&mut buf, "-{}", line).unwrap(),
            Diff::Left(line) => writeln!(&mut buf, "+{}", line).unwrap(),
        });

    if !buf.is_empty() {
        return Err(PublicApiError::Changed {
            package: package.to_string(),
            diff: buf,
        });
    };
    Ok(())
}
