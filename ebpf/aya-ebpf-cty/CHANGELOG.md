# Change Log

All notable changes to this project will be documented in this file.
This project adheres to $[Semantic Versioning](http://semver.org/).

## [Unreleased]

## v0.2.3 (2025-11-17)

### New Features

 - <csr-id-2eaae09c31add79103331aa551e8f74de86cd037/>, <csr-id-6252b4c9722c7c2ee2458741ae328dcc0c3c5234/> Added the missing MIPS and LoongArch definitions so the cty shim covers every architecture supported by Aya.

### Maintenance

 - <csr-id-1fe12b99907dda6553a6069fa462d6241d3fa171/>, <csr-id-09eefd366f7410c2f4744bb2bae533d9ce92ae20/> Tidied the crate (removing the abandoned Travis setup) and refreshed the bindings so downstream riscv64 builds stay green.

## v0.2.2 (2024-10-09)

### Other

 - <csr-id-b513af12e8baa5c5097eaf0afdae61a830c3f877/> add archs powerpc64 and s390x to aya
   bpfman, a project using aya, has a requirement to support powerpc64 and
   s390x architectures. Adding these two architectures to aya.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 3 commits contributed to the release.
 - 185 days passed between releases.
 - 1 commit was understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Merge pull request #974 from Billy99/billy99-arch-ppc64-s390x ([`ab5e688`](https://github.com/aya-rs/aya/commit/ab5e688fd49fcfb402ad47d51cb445437fbd8cb7))
    - Add archs powerpc64 and s390x to aya ([`b513af1`](https://github.com/aya-rs/aya/commit/b513af12e8baa5c5097eaf0afdae61a830c3f877))
    - Allowlist expected cfgs ([`e4f9ed8`](https://github.com/aya-rs/aya/commit/e4f9ed8d79e4cd19ab5124352fca9e6cbdc1030b))
</details>

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

