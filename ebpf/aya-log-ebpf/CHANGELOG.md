# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 0.2.0 (2026-06-24)

### Chore

 - <csr-id-c3f0c7dc3fb285da091454426eeda0723389f0f1/> Prepare for aya-log-ebpf release

### New Features

 - <csr-id-a98b638fa95fd8edb8c015ee03154d2f03ecffc8/> add support for logging raw pointer types
   * Requires the usage of `:p` display hint.
   * Will, like stdlib, log with `0x` prefix.

### Other

 - <csr-id-294e0c19413d5a7c073d17d79ad4d154283499ce/> Add helper for safe loading of globals
 - <csr-id-03e84871773e09badf08bdef8e83b4f1256850a4/> rename `set_` methods on `EbpfLoader`
   This loader is more of a builder, so these `set_` methods didn't
   quite fit. See [this discussion][1] for the motivation.
 - <csr-id-fe99fa1d2eee94c4bf60d698784cae3c43f3a71c/> run clippy with target=bpf
   This build warnings from integration tests and makes `aya-ebpf`'s build
   script stricter.
 - <csr-id-353b83383dccc430619f3c6d95e17edd6ca8a96c/> zero copy!
 - <csr-id-f6606473af43090190337dd42f593df2f907ac0a/> properly hint log level to verifier
   The log level implementation in b36cbc3eb8413d4fba4f2d820fec8176751457ac
   was incomplete as the verifier could reject programs which exceeded
   their instruction limits within logging statements. This commit
   addresses this issue by making the log level static variable immutable
   (s.t. the compiler puts it in a read-only section) and adds an
   additional test which the verifier will reject as an infinite loop iff
   it is unable to detect that the static variable would otherwise allow
   the logging.
 - <csr-id-9be2d723ce5d7bf5f85d69d54aa5fd7f60d48edc/> Replace AsyncPerfEventArray with RingBuf
   This doesn't get us to zero copy because the reserve/submit APIs do not
   support DSTs for reasons I don't remember.
   
   Now that it is unused in userspace, move `LOG_BUF_CAPACITY` to
   `aya-log-ebpf` by making its type `LogValueLength` which obviates the
   need for `log_value_length_sufficient`.
 - <csr-id-8fb19264da203ae3b6089b1b09b7cee13d235b09/> tidy up `macro_support`
   Move top level items into and remove unused items from `macro_support`.
 - <csr-id-49a828ec5655f6ecd0c38083c6c0dca217bad777/> reorder-keys
   Group non-workspace keys before workspace ones for readability.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 19 commits contributed to the release.
 - 10 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Remove no-longer-firing lint expectations ([`d43d8a9`](https://github.com/aya-rs/aya/commit/d43d8a9674217dc1fc91f4747f3c92a8c9d5e3f7))
    - Rename EbpfGlobal to Global ([`b9cb76b`](https://github.com/aya-rs/aya/commit/b9cb76b302bdd1288b6486fb3a0627ea40cc3dbc))
    - Add helper for safe loading of globals ([`294e0c1`](https://github.com/aya-rs/aya/commit/294e0c19413d5a7c073d17d79ad4d154283499ce))
    - Dial the lints to 100 ([`2f8759c`](https://github.com/aya-rs/aya/commit/2f8759cc62e2a420eef463e271d354fcf65eca9d))
    - Release crates ([`d238b2e`](https://github.com/aya-rs/aya/commit/d238b2ea6f1b2c1aa09a9050415b1c96329af0aa))
    - Rename `set_` methods on `EbpfLoader` ([`03e8487`](https://github.com/aya-rs/aya/commit/03e84871773e09badf08bdef8e83b4f1256850a4))
    - Add support for logging raw pointer types ([`a98b638`](https://github.com/aya-rs/aya/commit/a98b638fa95fd8edb8c015ee03154d2f03ecffc8))
    - Run clippy with target=bpf ([`fe99fa1`](https://github.com/aya-rs/aya/commit/fe99fa1d2eee94c4bf60d698784cae3c43f3a71c))
    - Zero copy! ([`353b833`](https://github.com/aya-rs/aya/commit/353b83383dccc430619f3c6d95e17edd6ca8a96c))
    - Properly hint log level to verifier ([`f660647`](https://github.com/aya-rs/aya/commit/f6606473af43090190337dd42f593df2f907ac0a))
    - Implement load-time log level mask ([`b36cbc3`](https://github.com/aya-rs/aya/commit/b36cbc3eb8413d4fba4f2d820fec8176751457ac))
    - Replace AsyncPerfEventArray with RingBuf ([`9be2d72`](https://github.com/aya-rs/aya/commit/9be2d723ce5d7bf5f85d69d54aa5fd7f60d48edc))
    - Tidy up `macro_support` ([`8fb1926`](https://github.com/aya-rs/aya/commit/8fb19264da203ae3b6089b1b09b7cee13d235b09))
    - Reorder-keys ([`49a828e`](https://github.com/aya-rs/aya/commit/49a828ec5655f6ecd0c38083c6c0dca217bad777))
    - Introduce workspace lints, warn on unused crates ([`a43e40a`](https://github.com/aya-rs/aya/commit/a43e40ae1d1441ab4aea6a1a5d9ea36b56d62ff8))
    - Bump edition to 2024 ([`f0a9f19`](https://github.com/aya-rs/aya/commit/f0a9f19ddc7f02143a02dcc2bf6be88fa2d84063))
    - Release aya-log-common v0.1.15, aya-log-ebpf v0.1.1 ([`04bbbcc`](https://github.com/aya-rs/aya/commit/04bbbccffa6298dbfeb967ca9967611e283ac81d))
    - Prepare for aya-log-ebpf release ([`c3f0c7d`](https://github.com/aya-rs/aya/commit/c3f0c7dc3fb285da091454426eeda0723389f0f1))
    - Release aya-ebpf-cty v0.2.2, aya-ebpf-bindings v0.1.1, aya-ebpf-macros v0.1.1, aya-ebpf v0.1.1 ([`59082f5`](https://github.com/aya-rs/aya/commit/59082f572c01e8356312ed53bdb818cfbea944b5))
</details>

## 0.1.2 (2025-11-17)

<csr-id-9be2d723ce5d7bf5f85d69d54aa5fd7f60d48edc/>
<csr-id-f0a9f19ddc7f02143a02dcc2bf6be88fa2d84063/>
<csr-id-8fb19264da203ae3b6089b1b09b7cee13d235b09/>

### Breaking Changes

 - <csr-id-9be2d723ce5d7bf5f85d69d54aa5fd7f60d48edc/> Logging from eBPF programs now writes into a ring buffer to match the host transport, requiring Linux 5.8 or later.

### New Features

 - <csr-id-b36cbc3eb8413d4fba4f2d820fec8176751457ac/> , <csr-id-f6606473af43090190337dd42f593df2f907ac0a/> Added a load-time log level mask and improved verifier hints so disabled log levels are optimised out entirely.
 - <csr-id-353b83383dccc430619f3c6d95e17edd6ca8a96c/> Logging paths now use zero-copy writes into the ring buffer, lowering instruction counts inside probes.
 - <csr-id-a98b638fa95fd8edb8c015ee03154d2f03ecffc8/> Added raw-pointer formatting so eBPF logs can mirror the new host-side diagnostics.

### Maintenance

 - <csr-id-f0a9f19ddc7f02143a02dcc2bf6be88fa2d84063/>, <csr-id-8fb19264da203ae3b6089b1b09b7cee13d235b09/> Kept the crate in sync with the workspace edition/lint settings and tidied the macro support helpers.

## 0.1.1 (2024-10-09)

<csr-id-c3f0c7dc3fb285da091454426eeda0723389f0f1/>

Maintenance release. Update to latest aya-ebpf version v0.1.1.

### Chore

 - <csr-id-c3f0c7dc3fb285da091454426eeda0723389f0f1/> Prepare for aya-log-ebpf release

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

