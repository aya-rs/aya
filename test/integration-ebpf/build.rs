use std::env;
use xtask::AYA_BUILD_INTEGRATION_BPF;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies

fn main() {
    println!("cargo:rerun-if-env-changed={}", AYA_BUILD_INTEGRATION_BPF);

    let build_integration_bpf = env::var(AYA_BUILD_INTEGRATION_BPF)
        .as_deref()
        .map(str::parse)
        .map(Result::unwrap)
        .unwrap_or_default();

    if build_integration_bpf {
        let out_dir = env::var_os("OUT_DIR").unwrap();
        let out_dir = std::path::PathBuf::from(out_dir);

        let bpf_linker = env::var("CARGO_BIN_FILE_BPF_LINKER").unwrap();

        // There seems to be no way to pass `-Clinker={}` to rustc from here.
        //
        // We assume rustc is going to look for `bpf-linker` on the PATH, so we can create a symlink
        // and put it on the PATH.
        let bin_dir = out_dir.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let bpf_linker_symlink = bin_dir.join("bpf-linker");
        match std::fs::remove_file(&bpf_linker_symlink) {
            Ok(()) => {}
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    panic!("failed to remove symlink: {err}")
                }
            }
        }
        std::os::unix::fs::symlink(bpf_linker, bpf_linker_symlink).unwrap();
        let path = env::var_os("PATH");
        let path = path.as_ref();
        let paths = std::iter::once(bin_dir).chain(path.into_iter().flat_map(env::split_paths));
        let path = env::join_paths(paths).unwrap();
        println!("cargo:rustc-env=PATH={}", path.to_str().unwrap());
    }
}
