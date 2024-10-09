# Change Log

All notable changes to this project will be documented in this file.
This project adheres to $[Semantic Versioning](http://semver.org/).

## [Unreleased]

## [v0.2.1] - 2019-11-16

### Added

- Support for the `xtensa`, `riscv32` and `riscv64` architectures

## [v0.2.0] - 2019-02-06

### Changed

- [breaking-change] `cty::c_void` is now a type alias of `core::ffi::c_void`.

## [v0.1.5] - 2017-05-29

### Added

- More types like `int32_t`

## [v0.1.4] - 2017-05-29

### Added

- Support for the `msp430` architecture.

### Fixed

- [breaking-change] The type definitions of `c_long` and `c_ulong`.

## [v0.1.3] - 2017-05-29 - YANKED

### Added

- Support for the `nvptx` and `nvptx64` architectures.

## [v0.1.2] - 2017-05-29 - YANKED

### Fixed

- [breaking-change] The type definitions of `c_int` and `c_uint`.

## [v0.1.1] - 2017-05-29 - YANKED

### Fixed

- [breaking-change] The type definitions of `c_long`, `c_ulong` and
  `c_longlong`.

## v0.1.0 - 2017-05-24 - YANKED

- Initial release

[Unreleased]: https://github.com/japaric/cty/compare/v0.2.1...HEAD
[v0.2.1]: https://github.com/japaric/cty/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/japaric/cty/compare/v0.1.5...v0.2.0
[v0.1.5]: https://github.com/japaric/cty/compare/v0.1.4...v0.1.5
[v0.1.4]: https://github.com/japaric/cty/compare/v0.1.3...v0.1.4
[v0.1.3]: https://github.com/japaric/cty/compare/v0.1.2...v0.1.3
[v0.1.2]: https://github.com/japaric/cty/compare/v0.1.1...v0.1.2
[v0.1.1]: https://github.com/japaric/cty/compare/v0.1.0...v0.1.1

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

