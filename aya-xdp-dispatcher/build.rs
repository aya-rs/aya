use std::{env, fs, path::PathBuf};

use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;
use aya_xdp_dispatcher_ebpf as _;
use xtask::AYA_BUILD_INTEGRATION_BPF;

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-env-changed={AYA_BUILD_INTEGRATION_BPF}");

    let build_integration_bpf = env::var_os(AYA_BUILD_INTEGRATION_BPF)
        .map(|build_integration_bpf| {
            let build_integration_bpf = std::str::from_utf8(
                build_integration_bpf.as_encoded_bytes(),
            )
            .with_context(|| {
                format!(
                    "{AYA_BUILD_INTEGRATION_BPF}={}",
                    build_integration_bpf.display()
                )
            })?;
            let build_integration_bpf: bool = build_integration_bpf
                .parse()
                .with_context(|| format!("{AYA_BUILD_INTEGRATION_BPF}={build_integration_bpf}"))?;
            Ok(build_integration_bpf)
        })
        .transpose()?
        .unwrap_or_default();

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "aya-xdp-dispatcher-ebpf")
        .ok_or_else(|| anyhow!("aya-xdp-dispatcher-ebpf package not found"))?;

    if build_integration_bpf {
        let cargo_metadata::Package {
            name,
            manifest_path,
            ..
        } = ebpf_package;
        let ebpf_package = aya_build::Package {
            name: name.as_str(),
            root_dir: manifest_path
                .parent()
                .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
                .as_str(),
            ..Default::default()
        };
        aya_build::build_ebpf([ebpf_package], Toolchain::default())
    } else {
        let out_dir = env::var_os("OUT_DIR").ok_or_else(|| anyhow!("OUT_DIR not set"))?;
        let out_dir = PathBuf::from(out_dir);
        let dst = out_dir.join("aya-xdp-dispatcher-ebpf");
        fs::write(&dst, []).with_context(|| format!("failed to create {}", dst.display()))?;
        Ok(())
    }
}
