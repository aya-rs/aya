# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## v0.1.2 (2025-11-17)

### New Features

 - <csr-id-77b1c6194c8f9bb69ffc6a60c3b8189b73e00e8f/> Added Flow Dissector macro support so attaching those programs no longer requires manual boilerplate.
 - <csr-id-5a43bedc0180ba41854e6c23f0476c2cbeb1e2bd/> Switched error reporting to `proc-macro2-diagnostics`, providing richer compiler output when macro expansion fails.

### Maintenance

 - <csr-id-dae394e199878283475a8cc5d1ca0ab82db305db/> Dropped the stale dev-dependency on `aya-ebpf` and kept the crate in sync with the workspace lint/edition configuration.

## v0.1.1 (2024-10-09)

### Chore

 - <csr-id-a6f4739b5b138e718632758cad266ee3cb7b1b65/> aya-ebpf-macros: uncomment aya-ebpf dev-dep
   This wasn't meant to be committed, cargo-smart-release. Commenting is
   needed to fix the cyclic dep aya-ebpf-macros -> aya-ebpf ->
   aya-ebpf-macros. See
   https://github.com/rust-lang/cargo/issues/4242#issuecomment-413203081

### Other

 - <csr-id-b84ede10b9c4813f221fade16b60d5ced4ecdc58/> separate probe to probe ctx & retprobe to retprobe ctx
   Added logic in expand function in both kprobe.rs and uprobe.rs for valid
   macros. Now, kprobe & uprobe proc macros only accept ProbeContext, and
   kretprobe & uretprobe only accept RetProbeContext.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 2 commits contributed to the release.
 - 185 days passed between releases.
 - 2 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Separate probe to probe ctx & retprobe to retprobe ctx ([`b84ede1`](https://github.com/aya-rs/aya/commit/b84ede10b9c4813f221fade16b60d5ced4ecdc58))
    - Aya-ebpf-macros: uncomment aya-ebpf dev-dep ([`a6f4739`](https://github.com/aya-rs/aya/commit/a6f4739b5b138e718632758cad266ee3cb7b1b65))
</details>

## v0.1.0 (2024-04-06)

<csr-id-ea8073793e44c593e983e69eaa43a4f72799bfc5/>
<csr-id-c7fe60d47e0cc32fc7123e37532d104eaa392b50/>

### Chore

 - <csr-id-ea8073793e44c593e983e69eaa43a4f72799bfc5/> Rename bpf -> ebpf

### Chore

 - <csr-id-c7fe60d47e0cc32fc7123e37532d104eaa392b50/> add changelogs

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 9 commits contributed to the release.
 - 2 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release aya-ebpf-macros v0.1.0 ([`9d24bbe`](https://github.com/aya-rs/aya/commit/9d24bbe316ddf5caca7413198d6f79a0064def88))
    - Release aya-ebpf-macros v0.1.0 ([`90f68db`](https://github.com/aya-rs/aya/commit/90f68dbd074e4cd74540d98fb9f17b6c2de3d054))
    - Release aya-ebpf-macros v0.1.0, aya-ebpf v0.1.0 ([`eb3947b`](https://github.com/aya-rs/aya/commit/eb3947bf14e8e7ab0f70e12306e38fb8056edf57))
    - Release aya-ebpf-bindings v0.1.0, aya-ebpf-macros v0.1.0, aya-ebpf v0.1.0 ([`a34c5e4`](https://github.com/aya-rs/aya/commit/a34c5e43b85dd176b9b18f1cc9c9d80d52f10a1f))
    - Release aya-ebpf-bindings v0.1.0, aya-ebpf-macros v0.1.0, aya-ebpf v0.1.0 ([`b8964d3`](https://github.com/aya-rs/aya/commit/b8964d3fd27353beb9054dd18fe8d16251f9164b))
    - Add changelogs ([`c7fe60d`](https://github.com/aya-rs/aya/commit/c7fe60d47e0cc32fc7123e37532d104eaa392b50))
    - Release aya-ebpf-cty v0.2.1, aya-ebpf-bindings v0.1.0, aya-ebpf-macros v0.1.0, aya-ebpf v0.1.0 ([`e372fcf`](https://github.com/aya-rs/aya/commit/e372fcf653304c6d7c2647cd7812ca11474f41fc))
    - Merge pull request #528 from dave-tucker/rename-all-the-things ([`63d8d4d`](https://github.com/aya-rs/aya/commit/63d8d4d34bdbbee149047dc0a5e9c2b191f3b32d))
    - Rename bpf -> ebpf ([`ea80737`](https://github.com/aya-rs/aya/commit/ea8073793e44c593e983e69eaa43a4f72799bfc5))
</details>

