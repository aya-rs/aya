use std::env;

use which::which;
use xtask::AYA_BUILD_INTEGRATION_BPF;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// <https://github.com/rust-lang/cargo/issues/12385> make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn main() {
    println!("cargo:rerun-if-env-changed={AYA_BUILD_INTEGRATION_BPF}");

    let build_integration_bpf = env::var(AYA_BUILD_INTEGRATION_BPF)
        .as_deref()
        .map(str::parse)
        .is_ok_and(Result::unwrap);

    if build_integration_bpf {
        let bpf_linker = which("bpf-linker").unwrap();
        println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
    }
}
