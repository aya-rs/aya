# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## v0.2.0 (2026-06-24)

### New Features

 - <csr-id-c1eb42780c8e0eba340808eb4b75df15ac434e61/> add typos-cli configuration and CI

### Other

 - <csr-id-a73f8642328adfc033ed879c1f3638e9c76ac7fe/> add FExitContext::ret
   FExit programs need a stable API for reading the return value of the
   function they are attached to. Add FExitContext::ret() so callers do
   not need to depend on the raw layout of the tracing context.
 - <csr-id-a375a2d5b94fa8f2d562c688dbce423dd46919e9/> emit uprobe.multi sections
 - <csr-id-4940ee6c69196634de9bf2f3c434cb5a57f194e5/> add BPF_PROG_TYPE_SK_REUSEPORT support
   Implement SK_REUSEPORT programs for programmable socket selection
   within SO_REUSEPORT groups.
   
   SkReuseport attaches and detaches via setsockopt rather than
   bpf_link, making it group-scoped: any socket in the group can
   attach or detach the program, and dropping SkReuseport does not
   detach it. Section parsing handles both sk_reuseport and
   sk_reuseport/migrate with the correct expected_attach_type.
   
   ReusePortSockArray is available in legacy and BTF variants.
   select_reuseport() is deduplicated across both via a pub(crate)
   trait. SkReuseportContext exposes sk_reuseport_md field
   accessors; sk() and migrating_sk() require Linux 5.14+.
   
   Integration tests verify socket steering, slot clearing with
   fallback, and migrate-path selection.
 - <csr-id-2b424ed8b59132db3621f74886ff280f3a035507/> split vectors to avoid panicking
   Statically avoid panicking branch. While I'm here emit errors for all
   unknown macro arguments, not just the first one.

### Test

 - <csr-id-f10988d56a2ac7575cfd79c0eaec66b62a9b6227/> replace test-case with rstest
   test-case relies on cooperating attribute macros when wrapping
   generated parameterized tests. Stacking it with test_log can register
   each generated case twice, so passing tests may run more than once and
   mask order-sensitive or flaky behavior.
   
   Move the parameterized tests to rstest, but do not rely on rstest's
   implicit test-attribute detection. rstest treats attributes whose path
   ends in test as test attributes; that has its own failure mode if a
   non-test decorator matches, potentially producing cases that do not run
   as intended.
   
   Use explicit #[test_attr(...)] wrappers for every rstest case that
   needs test_log or tokio, so generated tests get the intended harness
   attribute instead of depending on implicit detection.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 7 commits contributed to the release.
 - 6 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Replace test-case with rstest ([`f10988d`](https://github.com/aya-rs/aya/commit/f10988d56a2ac7575cfd79c0eaec66b62a9b6227))
    - Add FExitContext::ret ([`a73f864`](https://github.com/aya-rs/aya/commit/a73f8642328adfc033ed879c1f3638e9c76ac7fe))
    - Add typos-cli configuration and CI ([`c1eb427`](https://github.com/aya-rs/aya/commit/c1eb42780c8e0eba340808eb4b75df15ac434e61))
    - Emit uprobe.multi sections ([`a375a2d`](https://github.com/aya-rs/aya/commit/a375a2d5b94fa8f2d562c688dbce423dd46919e9))
    - Add BPF_PROG_TYPE_SK_REUSEPORT support ([`4940ee6`](https://github.com/aya-rs/aya/commit/4940ee6c69196634de9bf2f3c434cb5a57f194e5))
    - Dial the lints to 100 ([`2f8759c`](https://github.com/aya-rs/aya/commit/2f8759cc62e2a420eef463e271d354fcf65eca9d))
    - Split vectors to avoid panicking ([`2b424ed`](https://github.com/aya-rs/aya/commit/2b424ed8b59132db3621f74886ff280f3a035507))
</details>

## v0.1.2 (2025-11-17)

<csr-id-dae394e199878283475a8cc5d1ca0ab82db305db/>

### New Features

 - <csr-id-77b1c6194c8f9bb69ffc6a60c3b8189b73e00e8f/> Added Flow Dissector macro support so attaching those programs no longer requires manual boilerplate.
 - <csr-id-5a43bedc0180ba41854e6c23f0476c2cbeb1e2bd/> Switched error reporting to `proc-macro2-diagnostics`, providing richer compiler output when macro expansion fails.

### Maintenance

 - <csr-id-dae394e199878283475a8cc5d1ca0ab82db305db/> Dropped the stale dev-dependency on `aya-ebpf` and kept the crate in sync with the workspace lint/edition configuration.

### Other

 - <csr-id-14a844256a5140c45cb12b05c265a245b6022f9e/> remove glob imports
 - <csr-id-ab38afe95d16226f5a703bbb37c7842ee441c364/> support hardware breakpoints
   Implement `PerfEventConfig::Breakpoint`, allowing users to attach
   hardware breakpoints. Generate `HW_BREAKPOINT_*` and `struct
   bpf_perf_event_data` in support of this feature and update the type of
   `PerfEventContext` accordingly.
   
   Add a test exercising R, W, RW, and X breakpoints. Note that R
   breakpoints are unsupported on x86, and this is asserted in the test.
   
   Extend the VM integration test harness and supporting infrastructure
   (e.g. `download_kernel_images.sh`) to download kernel debug packages and
   mount `System.map` in initramfs. This is needed (at least) on the aarch
   6.1 Debian kernel which was not compiled with `CONFIG_KALLSYMS_ALL=y`
   for some reason, and the locations of globals are not available in
   kallsyms. To attach breakpoints to these symbols in the test pipeline,
   we need to read them from System.map and apply the KASLR offset to get
   their real address. The `System.map` file is not provided in the kernel
   package by default, so we need to extract it from the corresponding
   debug package. The KASLR offset is computed using `gunzip` which appears
   in kallsyms on all Debian kernels tested.
 - <csr-id-fc5387c80626957017ceeb988322bc288f438059/> cgroup attachment type support
 - <csr-id-0b2a544ddd9df74ebcdb46128b6bcc48336b2762/> Add BTF array definition
   Before this change, Aya supported only legacy BPF map definitions, which
   are instances of the `bpf_map_def` struct and end up in the `maps` ELF
   section.
   
   This change introduces a BTF map definition for arrays, with custom
   structs indicating the metadata of the map, which end up in the `.maps`
   section.
 - <csr-id-49a828ec5655f6ecd0c38083c6c0dca217bad777/> reorder-keys
   Group non-workspace keys before workspace ones for readability.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 16 commits contributed to the release over the course of 349 calendar days.
 - 6 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release crates ([`d238b2e`](https://github.com/aya-rs/aya/commit/d238b2ea6f1b2c1aa09a9050415b1c96329af0aa))
    - Remove glob imports ([`14a8442`](https://github.com/aya-rs/aya/commit/14a844256a5140c45cb12b05c265a245b6022f9e))
    - Support hardware breakpoints ([`ab38afe`](https://github.com/aya-rs/aya/commit/ab38afe95d16226f5a703bbb37c7842ee441c364))
    - Add clippy coverage for doctests ([`112ab47`](https://github.com/aya-rs/aya/commit/112ab47fcdf8ba4765e6f6416cbb7000c96292f8))
    - Cgroup attachment type support ([`fc5387c`](https://github.com/aya-rs/aya/commit/fc5387c80626957017ceeb988322bc288f438059))
    - Lint all crates; enable strict pointer lints ([`5f5305c`](https://github.com/aya-rs/aya/commit/5f5305c2a8ca0a739219093599dd57182d440ac1))
    - Add BTF array definition ([`0b2a544`](https://github.com/aya-rs/aya/commit/0b2a544ddd9df74ebcdb46128b6bcc48336b2762))
    - Remove superfluous commas ([`a3aa387`](https://github.com/aya-rs/aya/commit/a3aa387a2e8035660425cefb4f6171d5fdb7537e))
    - Appease `clippy::uninlined-format-args` ([`583709f`](https://github.com/aya-rs/aya/commit/583709f6a09c432b4e06ab9353bb4e397d58c451))
    - Add support for Flow Dissector programs ([`77b1c61`](https://github.com/aya-rs/aya/commit/77b1c6194c8f9bb69ffc6a60c3b8189b73e00e8f))
    - Reorder-keys ([`49a828e`](https://github.com/aya-rs/aya/commit/49a828ec5655f6ecd0c38083c6c0dca217bad777))
    - Introduce workspace lints, warn on unused crates ([`a43e40a`](https://github.com/aya-rs/aya/commit/a43e40ae1d1441ab4aea6a1a5d9ea36b56d62ff8))
    - Bump edition to 2024 ([`f0a9f19`](https://github.com/aya-rs/aya/commit/f0a9f19ddc7f02143a02dcc2bf6be88fa2d84063))
    - Use #[expect(...)] rather than #[allow(...)] ([`4101a5a`](https://github.com/aya-rs/aya/commit/4101a5a55d43cd9ead56497820c4d43018f74cbb))
    - Replace proc-macro-error with proc-macro2-diagnostics ([`5a43bed`](https://github.com/aya-rs/aya/commit/5a43bedc0180ba41854e6c23f0476c2cbeb1e2bd))
    - Remove aya-ebpf version ([`dae394e`](https://github.com/aya-rs/aya/commit/dae394e199878283475a8cc5d1ca0ab82db305db))
</details>

## v0.1.1 (2024-10-09)

<csr-id-a6f4739b5b138e718632758cad266ee3cb7b1b65/>
<csr-id-b84ede10b9c4813f221fade16b60d5ced4ecdc58/>

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

 - 3 commits contributed to the release.
 - 2 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release aya-ebpf-cty v0.2.2, aya-ebpf-bindings v0.1.1, aya-ebpf-macros v0.1.1, aya-ebpf v0.1.1 ([`59082f5`](https://github.com/aya-rs/aya/commit/59082f572c01e8356312ed53bdb818cfbea944b5))
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

