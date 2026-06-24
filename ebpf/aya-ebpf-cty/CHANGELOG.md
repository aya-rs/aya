# Change Log

All notable changes to this project will be documented in this file.
This project adheres to $[Semantic Versioning](http://semver.org/).

## [Unreleased]

## v0.3.0 (2026-06-24)

### Other

 - <csr-id-879925717b88957fcb71e1dd7df3022372dfb796/> add mips64 arch
   Wire up mips64 now that bindings are generated. MIPS64 uses the N64 ABI
   with the same pt_regs layout as MIPS (regs[4..11] for arguments, regs[2]
   for return value), so the PtRegsLayout impl is shared via cfg(any(...)).

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 2 commits contributed to the release.
 - 1 commit was understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Add mips64 arch ([`8799257`](https://github.com/aya-rs/aya/commit/879925717b88957fcb71e1dd7df3022372dfb796))
    - Dial the lints to 100 ([`2f8759c`](https://github.com/aya-rs/aya/commit/2f8759cc62e2a420eef463e271d354fcf65eca9d))
</details>

## v0.2.3 (2025-11-17)

<csr-id-1fe12b99907dda6553a6069fa462d6241d3fa171/>
<csr-id-09eefd366f7410c2f4744bb2bae533d9ce92ae20/>

### New Features

 - <csr-id-2eaae09c31add79103331aa551e8f74de86cd037/> , <csr-id-6252b4c9722c7c2ee2458741ae328dcc0c3c5234/> Added the missing MIPS and LoongArch definitions so the cty shim covers every architecture supported by Aya.

### Maintenance

 - <csr-id-1fe12b99907dda6553a6069fa462d6241d3fa171/>, <csr-id-09eefd366f7410c2f4744bb2bae533d9ce92ae20/> Tidied the crate (removing the abandoned Travis setup) and refreshed the bindings so downstream riscv64 builds stay green.

### Other

 - <csr-id-f610453ec234921c07aeb4d5401d0a8940d513df/> extract CARGO_CFG_BPF_TARGET_ARCH logic
 - <csr-id-49a828ec5655f6ecd0c38083c6c0dca217bad777/> reorder-keys
   Group non-workspace keys before workspace ones for readability.
 - <csr-id-6252b4c9722c7c2ee2458741ae328dcc0c3c5234/> hook up loongarch64
   This causes rustfmt to format those files.
   
   Squish some other conditional compilation to get rustfmt sorting.
 - <csr-id-b513af12e8baa5c5097eaf0afdae61a830c3f877/> add archs powerpc64 and s390x to aya
   bpfman, a project using aya, has a requirement to support powerpc64 and
   s390x architectures. Adding these two architectures to aya.

### Chore

 - <csr-id-2eaae09c31add79103331aa551e8f74de86cd037/> Add mips support

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 15 commits contributed to the release.
 - 5 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 1 unique issue was worked on: [#1139](https://github.com/aya-rs/aya/issues/1139)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#1139](https://github.com/aya-rs/aya/issues/1139)**
    - Fix aya-ebpf-* riscv64 build ([`1fe12b9`](https://github.com/aya-rs/aya/commit/1fe12b99907dda6553a6069fa462d6241d3fa171))
 * **Uncategorized**
    - Release crates ([`d238b2e`](https://github.com/aya-rs/aya/commit/d238b2ea6f1b2c1aa09a9050415b1c96329af0aa))
    - Extract CARGO_CFG_BPF_TARGET_ARCH logic ([`f610453`](https://github.com/aya-rs/aya/commit/f610453ec234921c07aeb4d5401d0a8940d513df))
    - Reorder-keys ([`49a828e`](https://github.com/aya-rs/aya/commit/49a828ec5655f6ecd0c38083c6c0dca217bad777))
    - Introduce workspace lints, warn on unused crates ([`a43e40a`](https://github.com/aya-rs/aya/commit/a43e40ae1d1441ab4aea6a1a5d9ea36b56d62ff8))
    - Hook up loongarch64 ([`6252b4c`](https://github.com/aya-rs/aya/commit/6252b4c9722c7c2ee2458741ae328dcc0c3c5234))
    - Bump edition to 2024 ([`f0a9f19`](https://github.com/aya-rs/aya/commit/f0a9f19ddc7f02143a02dcc2bf6be88fa2d84063))
    - Use #[expect(...)] rather than #[allow(...)] ([`4101a5a`](https://github.com/aya-rs/aya/commit/4101a5a55d43cd9ead56497820c4d43018f74cbb))
    - Merge pull request #482 from ishanjain28/add_mips_support ([`2f757b2`](https://github.com/aya-rs/aya/commit/2f757b2091d28a17c90495ee2955e7f8d1bc5ec5))
    - Add mips support ([`2eaae09`](https://github.com/aya-rs/aya/commit/2eaae09c31add79103331aa551e8f74de86cd037))
    - Remove long-dead travis config ([`09eefd3`](https://github.com/aya-rs/aya/commit/09eefd366f7410c2f4744bb2bae533d9ce92ae20))
    - Release aya-ebpf-cty v0.2.2, aya-ebpf-bindings v0.1.1, aya-ebpf-macros v0.1.1, aya-ebpf v0.1.1 ([`59082f5`](https://github.com/aya-rs/aya/commit/59082f572c01e8356312ed53bdb818cfbea944b5))
    - Merge pull request #974 from Billy99/billy99-arch-ppc64-s390x ([`ab5e688`](https://github.com/aya-rs/aya/commit/ab5e688fd49fcfb402ad47d51cb445437fbd8cb7))
    - Add archs powerpc64 and s390x to aya ([`b513af1`](https://github.com/aya-rs/aya/commit/b513af12e8baa5c5097eaf0afdae61a830c3f877))
    - Allowlist expected cfgs ([`e4f9ed8`](https://github.com/aya-rs/aya/commit/e4f9ed8d79e4cd19ab5124352fca9e6cbdc1030b))
</details>

## v0.2.2 (2024-10-09)

<csr-id-b513af12e8baa5c5097eaf0afdae61a830c3f877/>

### Other

 - <csr-id-b513af12e8baa5c5097eaf0afdae61a830c3f877/> add archs powerpc64 and s390x to aya
   bpfman, a project using aya, has a requirement to support powerpc64 and
   s390x architectures. Adding these two architectures to aya.

## v0.2.1 (2024-04-06)

<csr-id-21f570a19cd8d6e8eeaa6127d936877a701ceac3/>

### Chore

 - <csr-id-21f570a19cd8d6e8eeaa6127d936877a701ceac3/> Rename bpf -> ebpf

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 3 commits contributed to the release.
 - 1 commit was understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release aya-ebpf-cty v0.2.1, aya-ebpf-bindings v0.1.0, aya-ebpf-macros v0.1.0, aya-ebpf v0.1.0 ([`e372fcf`](https://github.com/aya-rs/aya/commit/e372fcf653304c6d7c2647cd7812ca11474f41fc))
    - Merge pull request #528 from dave-tucker/rename-all-the-things ([`63d8d4d`](https://github.com/aya-rs/aya/commit/63d8d4d34bdbbee149047dc0a5e9c2b191f3b32d))
    - Rename bpf -> ebpf ([`21f570a`](https://github.com/aya-rs/aya/commit/21f570a19cd8d6e8eeaa6127d936877a701ceac3))
</details>

