#![expect(unused_crate_dependencies, reason = "used in bin")]

use std::{env, ffi::OsString, path::Path, process::Command};

use anyhow::{Context as _, Result, bail};

pub const AYA_BUILD_INTEGRATION_BPF: &str = "AYA_BUILD_INTEGRATION_BPF";
pub const LIBBPF_DIR: &str = "xtask/libbpf";

pub fn exec(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to run {cmd:?}"))?;
    if status.code() != Some(0) {
        bail!("{cmd:?} failed: {status:?}")
    }
    Ok(())
}

// libbpf-sys cross-compilation workarounds:
// - ac_cv_search_* variables skip autoconf checks
// - linux-libc-dev provides kernel UAPI headers (installed in CI)
// - CFLAGS adds ci/headers for elfutils
//
// See https://github.com/libbpf/libbpf-sys/issues/137.
pub fn libbpf_sys_env(workspace_root: &Path, cmd: &mut Command) {
    for name in [
        "ac_cv_search_argp_parse",
        "ac_cv_search__obstack_free",
        "ac_cv_search_gzdirect",
        "ac_cv_search_fts_close",
    ] {
        cmd.env(name, "none required");
    }

    const CFLAGS: &str = "CFLAGS";
    cmd.env(CFLAGS, {
        let headers = workspace_root.join("ci").join("headers");
        let mut cflags = OsString::new();
        cflags.push("-I");
        cflags.push(headers.as_os_str());
        if let Some(existing) = env::var_os(CFLAGS) {
            cflags.push(" ");
            cflags.push(existing);
        }
        cflags
    });

    if cfg!(target_os = "macos") {
        // Add make wrapper that overrides AR/RANLIB for zlib cross build.
        const PATH: &str = "PATH";
        cmd.env(PATH, {
            let mut path = OsString::new();
            path.push(workspace_root.join("ci").join("bin"));
            if let Some(existing) = env::var_os(PATH) {
                path.push(":");
                path.push(existing);
            }
            path
        });

        for (key, value) in [
            ("AR_x86_64_unknown_linux_musl", "x86_64-linux-musl-ar"),
            (
                "RANLIB_x86_64_unknown_linux_musl",
                "x86_64-linux-musl-ranlib",
            ),
        ] {
            cmd.env(key, value);
        }
    }
}

/// Returns a [`Command`]` that Installs the libbpf headers files from the `source_dir` to the
/// `headers_dir`.
pub fn install_libbpf_headers_cmd(
    source_dir: impl AsRef<Path>,
    headers_dir: impl AsRef<Path>,
) -> Command {
    let mut includedir = OsString::new();
    includedir.push("INCLUDEDIR=");
    includedir.push(headers_dir.as_ref().as_os_str());

    let mut cmd = Command::new("make");
    cmd.arg("-C")
        .arg(source_dir.as_ref().join("src"))
        .arg(includedir)
        .arg("install_headers");
    cmd
}

#[derive(Debug)]
pub struct Errors<E>(Vec<E>);

impl<E> Errors<E> {
    pub fn new(errors: Vec<E>) -> Self {
        Self(errors)
    }
}

impl<E> std::fmt::Display for Errors<E>
where
    E: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(errors) = self;
        for (i, error) in errors.iter().enumerate() {
            if i != 0 {
                writeln!(f)?;
            }
            write!(f, "{error:?}")?;
        }
        Ok(())
    }
}

impl<E> std::error::Error for Errors<E> where E: std::fmt::Debug {}
