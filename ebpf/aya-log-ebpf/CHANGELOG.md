# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes

 - <csr-id-9be2d723ce5d7bf5f85d69d54aa5fd7f60d48edc/> Logging from eBPF programs now writes into a ring buffer to match the host transport, requiring Linux 5.8 or later.

### New Features

 - <csr-id-b36cbc3eb8413d4fba4f2d820fec8176751457ac/>, <csr-id-f6606473af43090190337dd42f593df2f907ac0a/> Added a load-time log level mask and improved verifier hints so disabled log levels are optimised out entirely.
 - <csr-id-353b83383dccc430619f3c6d95e17edd6ca8a96c/> Logging paths now use zero-copy writes into the ring buffer, lowering instruction counts inside probes.
 - <csr-id-a98b638fa95fd8edb8c015ee03154d2f03ecffc8/> Added raw-pointer formatting so eBPF logs can mirror the new host-side diagnostics.

### Maintenance

 - <csr-id-f0a9f19ddc7f02143a02dcc2bf6be88fa2d84063/>, <csr-id-8fb19264da203ae3b6089b1b09b7cee13d235b09/> Kept the crate in sync with the workspace edition/lint settings and tidied the macro support helpers.

## 0.1.1 (2024-10-09)

Maintenance release. Update to latest aya-ebpf version v0.1.1.

### Chore

 - <csr-id-c3f0c7dc3fb285da091454426eeda0723389f0f1/> Prepare for aya-log-ebpf release

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 2 commits contributed to the release.
 - 179 days passed between releases.
 - 1 commit was understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Prepare for aya-log-ebpf release ([`c3f0c7d`](https://github.com/aya-rs/aya/commit/c3f0c7dc3fb285da091454426eeda0723389f0f1))
    - Release aya-ebpf-cty v0.2.2, aya-ebpf-bindings v0.1.1, aya-ebpf-macros v0.1.1, aya-ebpf v0.1.1 ([`59082f5`](https://github.com/aya-rs/aya/commit/59082f572c01e8356312ed53bdb818cfbea944b5))
</details>

## v0.1.0 (2024-04-12)

<csr-id-a4ae8adb0db75f2b82b10b0740447a1dbead62c0/>
<csr-id-41c61560eae01a30c703ea22c5bfeeff0ecf6b1b/>
<csr-id-022aff96aa7299ccc7ec7e85829bb842d39b1501/>
<csr-id-1d515fe810c6e646ca405d8f97803698deda148c/>

### Chore

 - <csr-id-a4ae8adb0db75f2b82b10b0740447a1dbead62c0/> add version keys to Cargo.toml(s)
 - <csr-id-41c61560eae01a30c703ea22c5bfeeff0ecf6b1b/> Rename bpf -> ebpf
 - <csr-id-022aff96aa7299ccc7ec7e85829bb842d39b1501/> Rename bpf dir to ebpf

### Chore

 - <csr-id-1d515fe810c6e646ca405d8f97803698deda148c/> add missing changelogs

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 8 commits contributed to the release.
 - 4 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release aya-log-ebpf v0.1.0 ([`843f4a6`](https://github.com/aya-rs/aya/commit/843f4a6cc6a8e295ae36ea0c986c8295cef66c0d))
    - Release aya-log-ebpf-macros v0.1.0 ([`2eac95f`](https://github.com/aya-rs/aya/commit/2eac95f6d9075053fbabc67b92b7aa66008b057e))
    - Add missing changelogs ([`1d515fe`](https://github.com/aya-rs/aya/commit/1d515fe810c6e646ca405d8f97803698deda148c))
    - Release aya-ebpf-bindings v0.1.0, aya-ebpf-macros v0.1.0, aya-ebpf v0.1.0 ([`a34c5e4`](https://github.com/aya-rs/aya/commit/a34c5e43b85dd176b9b18f1cc9c9d80d52f10a1f))
    - Add version keys to Cargo.toml(s) ([`a4ae8ad`](https://github.com/aya-rs/aya/commit/a4ae8adb0db75f2b82b10b0740447a1dbead62c0))
    - Merge pull request #528 from dave-tucker/rename-all-the-things ([`63d8d4d`](https://github.com/aya-rs/aya/commit/63d8d4d34bdbbee149047dc0a5e9c2b191f3b32d))
    - Rename bpf -> ebpf ([`41c6156`](https://github.com/aya-rs/aya/commit/41c61560eae01a30c703ea22c5bfeeff0ecf6b1b))
    - Rename bpf dir to ebpf ([`022aff9`](https://github.com/aya-rs/aya/commit/022aff96aa7299ccc7ec7e85829bb842d39b1501))
</details>

