# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.2.0 (2026-06-24)

### Other

 - <csr-id-879925717b88957fcb71e1dd7df3022372dfb796/> add mips64 arch
   Wire up mips64 now that bindings are generated. MIPS64 uses the N64 ABI
   with the same pt_regs layout as MIPS (regs[4..11] for arguments, regs[2]
   for return value), so the PtRegsLayout impl is shared via cfg(any(...)).
 - <csr-id-4cc14020fb855472b30ea4927bd2a2a3e6023ce2/> honor `RUSTC_BOOTSTRAP`
   Use `RUSTC_BOOTSTRAP` when deciding whether to pass `-Zbuild-std=core`.
   
   This keeps eBPF builds working in environments without rustup where a
   stable toolchain is used with bootstrap enabled to allow unstable
   features. It also preserves `-1` as an explicit opt-out and accepts
   crate-scoped bootstrap values.
 - <csr-id-dc129982687754ebef39d9f5e24e20d5f4acad84/> try to build when rustup is not found
   In some environments, rustup is not availible but cargo and its targets
   are. This changes aya-build to try to continue building if rustup is not
   found, even with stable Rust. A warning will now be issued if rustup is
   not found but the build will proceed regardless. Add a dependency on
   `rustc_version` and condition `-Z build-std=core` on the toolchain being
   nightly to allow custom toolchains with prebuilt ebpf sysroots.
 - <csr-id-388d1f9694f5eb49f1030caf9a17e71679e153e9/> Allow to opt out
   Allow to opt out from cargo-in-cargo by setting `AYA_BUILD_SKIP`
   environment variable to `1` or `true`. That makes it easier for people
   using custom toolchains not managed by rustup (e.g. package
   maintainers).
 - <csr-id-5c0ebe8684cd0b3477a7f2dce88230c632237283/> Avoid OUT_DIR collisions
   When the eBPF package name matches a bin target name, aya-build used
   OUT_DIR/<package-name> as Cargo's --target-dir and then tried to copy
   the built binary to OUT_DIR/<bin-name>. This makes the destination a
   directory and fails with EISDIR.
   
   Put the cargo --target-dir under a dedicated subdirectory inside OUT_DIR
   to keep build artifacts separate from copied outputs.
   
   Fixes https://github.com/aya-rs/aya/issues/1432.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 7 commits contributed to the release.
 - 5 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Add mips64 arch ([`8799257`](https://github.com/aya-rs/aya/commit/879925717b88957fcb71e1dd7df3022372dfb796))
    - Honor `RUSTC_BOOTSTRAP` ([`4cc1402`](https://github.com/aya-rs/aya/commit/4cc14020fb855472b30ea4927bd2a2a3e6023ce2))
    - Dial the lints to 100 ([`2f8759c`](https://github.com/aya-rs/aya/commit/2f8759cc62e2a420eef463e271d354fcf65eca9d))
    - Try to build when rustup is not found ([`dc12998`](https://github.com/aya-rs/aya/commit/dc129982687754ebef39d9f5e24e20d5f4acad84))
    - Enable unused_qualifications lint ([`e746618`](https://github.com/aya-rs/aya/commit/e746618143f010fe7f05635a1a6e1a8b723bfd31))
    - Allow to opt out ([`388d1f9`](https://github.com/aya-rs/aya/commit/388d1f9694f5eb49f1030caf9a17e71679e153e9))
    - Avoid OUT_DIR collisions ([`5c0ebe8`](https://github.com/aya-rs/aya/commit/5c0ebe8684cd0b3477a7f2dce88230c632237283))
</details>

## v0.1.3 (2025-11-17)

### Other

 - <csr-id-17573e0e47fd53c24097a1f92b3e0ecf66a298d4/> plumb features of ebpf crates
   This allows callers to select features of the ebpf crate.
 - <csr-id-948b8553ee72ab72d91c9a16e7e937a75eb0e155/> guess `bpf_target_arch` from `HOST`
   Remove the use of `CARGO_CFG_TARGET_ARCH` in ebpf crate build scripts,
   moving it back only to `aya_build::build_ebpf` where it refers to the
   userspace crate's target. In the ebpf crates restore the use of `HOST`
   as the default compilation target when neither `--cfg bpf_target_arch`
   nor `AYA_BPF_TARGET_ARCH` are provided.
 - <csr-id-fe3f5c4e7dfddd1d4e6496ceadb1752b8522495c/> read AYA_BPF_TARGET_ARCH
   This allows users to set `bpf_target_arch` from the environment without
   touching RUSTFLAGS.
 - <csr-id-4b0ddfc2b0f671d43fbcdeb78c9e46b099404f53/> simplify
   Cargo sets `CARGO_CFG_BPF_TARGET_ARCH` so we don't have to inspect
   `CARGO_ENCODED_RUSTFLAGS`.
 - <csr-id-0c7c8097b20b11a89238b2102af47efbf95f7a4d/> clarify naming
 - <csr-id-e2c50ac221cf80f33c7e08c65692bb939c396a9e/> use OsString::into_string
 - <csr-id-b4bcf52ef1747932ee581bee803cea3a56ab9f11/> pass bpf_target_arch with cfg
   Retire the use of `CARGO_CFG_BPF_TARGET_ARCH` -- using a `cfg` allows
   cargo to properly use a cache per cfg, making `./clippy.sh` much faster.
   
   ```
   Cold: ./clippy.sh --target x86_64-unknown-linux-gnu -p aya-build  75.38s user 137.28s system 211% cpu 1:40.43 total
   Warm: ./clippy.sh --target x86_64-unknown-linux-gnu -p aya-build   4.46s user   3.41s system  71% cpu   11.01 total
   ```
 - <csr-id-d9704be77d5020669405c0cdbd98daec66700a8a/> remove cargo_metadata from public API
 - <csr-id-f610453ec234921c07aeb4d5401d0a8940d513df/> extract CARGO_CFG_BPF_TARGET_ARCH logic
 - <csr-id-a7e3e6d4d90767d40a015a473a7d0623031ff6ee/> bump the cargo-crates group with 2 updates
   Updates the requirements on [cargo_metadata](https://github.com/oli-obk/cargo_metadata) and [object](https://github.com/gimli-rs/object) to permit the latest version.
   
   Updates `cargo_metadata` to 0.19.2
   - [Release notes](https://github.com/oli-obk/cargo_metadata/releases)
   - [Changelog](https://github.com/oli-obk/cargo_metadata/blob/main/CHANGELOG.md)
   - [Commits](https://github.com/oli-obk/cargo_metadata/compare/0.19.0...0.19.2)
   
   Updates `object` to 0.36.7
   - [Changelog](https://github.com/gimli-rs/object/blob/master/CHANGELOG.md)
   - [Commits](https://github.com/gimli-rs/object/compare/0.36.0...0.36.7)
   
   ---
   updated-dependencies:
   - dependency-name: cargo_metadata
     dependency-version: 0.19.2
     dependency-type: direct:production
     dependency-group: cargo-crates
   - dependency-name: object
     dependency-version: 0.36.7
     dependency-type: direct:production
     dependency-group: cargo-crates
   ...
 - <csr-id-eab5661a0eff32e5f85fdf903acfdacf259ddbe1/> enable BTF
 - <csr-id-6d36fe13d31fd4d1ed14d2dbe33f9536c5398993/> Allow setting Rust nightly version
   At present, `aya_build` will always use `+nightly` to build the
   eBPF kernel. This is problematic in environments such as CI, where
   tools always need to be installed first. Installing the current
   nightly Rust toolchain gives you a new toolchain every day. This
   poisones caches and makes CI jobs non-deterministic.
 - <csr-id-49a828ec5655f6ecd0c38083c6c0dca217bad777/> reorder-keys
   Group non-workspace keys before workspace ones for readability.
 - <csr-id-3d8cb08b7f067a5d57a7268d0b53131b527f4583/> add explicit irrefutable pattern
   This is required in Rust 1.80 at least.
 - <csr-id-015c0df0f41f9aa20556dadd282899afb2e2123d/> enable anyhow/std
   This is needed before Rust 1.81.
 - <csr-id-6970353b58852f8732a8d37f1b281662aab8a11d/> add description

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 23 commits contributed to the release.
 - 16 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release crates ([`d238b2e`](https://github.com/aya-rs/aya/commit/d238b2ea6f1b2c1aa09a9050415b1c96329af0aa))
    - Plumb features of ebpf crates ([`17573e0`](https://github.com/aya-rs/aya/commit/17573e0e47fd53c24097a1f92b3e0ecf66a298d4))
    - Guess `bpf_target_arch` from `HOST` ([`948b855`](https://github.com/aya-rs/aya/commit/948b8553ee72ab72d91c9a16e7e937a75eb0e155))
    - Read AYA_BPF_TARGET_ARCH ([`fe3f5c4`](https://github.com/aya-rs/aya/commit/fe3f5c4e7dfddd1d4e6496ceadb1752b8522495c))
    - Simplify ([`4b0ddfc`](https://github.com/aya-rs/aya/commit/4b0ddfc2b0f671d43fbcdeb78c9e46b099404f53))
    - Clarify naming ([`0c7c809`](https://github.com/aya-rs/aya/commit/0c7c8097b20b11a89238b2102af47efbf95f7a4d))
    - Use OsString::into_string ([`e2c50ac`](https://github.com/aya-rs/aya/commit/e2c50ac221cf80f33c7e08c65692bb939c396a9e))
    - Pass bpf_target_arch with cfg ([`b4bcf52`](https://github.com/aya-rs/aya/commit/b4bcf52ef1747932ee581bee803cea3a56ab9f11))
    - Remove cargo_metadata from public API ([`d9704be`](https://github.com/aya-rs/aya/commit/d9704be77d5020669405c0cdbd98daec66700a8a))
    - Extract CARGO_CFG_BPF_TARGET_ARCH logic ([`f610453`](https://github.com/aya-rs/aya/commit/f610453ec234921c07aeb4d5401d0a8940d513df))
    - Lint all crates; enable strict pointer lints ([`5f5305c`](https://github.com/aya-rs/aya/commit/5f5305c2a8ca0a739219093599dd57182d440ac1))
    - Merge pull request #1273 from aya-rs/dependabot/cargo/cargo-crates-af2cda06bf ([`d1ed76e`](https://github.com/aya-rs/aya/commit/d1ed76e626acb85bdb33ffe0470435fd963f64d6))
    - Bump the cargo-crates group with 2 updates ([`a7e3e6d`](https://github.com/aya-rs/aya/commit/a7e3e6d4d90767d40a015a473a7d0623031ff6ee))
    - Enable BTF ([`eab5661`](https://github.com/aya-rs/aya/commit/eab5661a0eff32e5f85fdf903acfdacf259ddbe1))
    - Allow setting Rust nightly version ([`6d36fe1`](https://github.com/aya-rs/aya/commit/6d36fe13d31fd4d1ed14d2dbe33f9536c5398993))
    - Reorder-keys ([`49a828e`](https://github.com/aya-rs/aya/commit/49a828ec5655f6ecd0c38083c6c0dca217bad777))
    - Introduce workspace lints, warn on unused crates ([`a43e40a`](https://github.com/aya-rs/aya/commit/a43e40ae1d1441ab4aea6a1a5d9ea36b56d62ff8))
    - Bump edition to 2024 ([`f0a9f19`](https://github.com/aya-rs/aya/commit/f0a9f19ddc7f02143a02dcc2bf6be88fa2d84063))
    - Use #[expect(...)] rather than #[allow(...)] ([`4101a5a`](https://github.com/aya-rs/aya/commit/4101a5a55d43cd9ead56497820c4d43018f74cbb))
    - Add explicit irrefutable pattern ([`3d8cb08`](https://github.com/aya-rs/aya/commit/3d8cb08b7f067a5d57a7268d0b53131b527f4583))
    - Enable anyhow/std ([`015c0df`](https://github.com/aya-rs/aya/commit/015c0df0f41f9aa20556dadd282899afb2e2123d))
    - Add description ([`6970353`](https://github.com/aya-rs/aya/commit/6970353b58852f8732a8d37f1b281662aab8a11d))
    - Extract aya-build for building eBPF crates ([`2b2af44`](https://github.com/aya-rs/aya/commit/2b2af44915166f1e942daf6598072aeea27f1ba5))
</details>

