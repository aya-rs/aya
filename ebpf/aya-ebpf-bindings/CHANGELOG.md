# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## v0.2.0 (2026-06-24)

### Other

 - <csr-id-879925717b88957fcb71e1dd7df3022372dfb796/> add mips64 arch
   Wire up mips64 now that bindings are generated. MIPS64 uses the N64 ABI
   with the same pt_regs layout as MIPS (regs[4..11] for arguments, regs[2]
   for return value), so the PtRegsLayout impl is shared via cfg(any(...)).

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 7 commits contributed to the release.
 - 1 commit was understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Aya-ebpf-bindings, aya-ebpf: expose PERF_MAX_STACK_DEPTH ([`61eea8a`](https://github.com/aya-rs/aya/commit/61eea8ada7ac42270add8f0bf37ea12fed2dc44f))
    - Add mips64 arch ([`8799257`](https://github.com/aya-rs/aya/commit/879925717b88957fcb71e1dd7df3022372dfb796))
    - Aya-obj, aya-ebpf-bindings: regenerate ([`20d8d64`](https://github.com/aya-rs/aya/commit/20d8d64c3b8bd3aaf495708115f8eae3ce7e54d2))
    - Remove no-longer-firing lint expectations ([`d43d8a9`](https://github.com/aya-rs/aya/commit/d43d8a9674217dc1fc91f4747f3c92a8c9d5e3f7))
    - Dial the lints to 100 ([`2f8759c`](https://github.com/aya-rs/aya/commit/2f8759cc62e2a420eef463e271d354fcf65eca9d))
    - Enable unused_qualifications lint ([`e746618`](https://github.com/aya-rs/aya/commit/e746618143f010fe7f05635a1a6e1a8b723bfd31))
    - Aya, aya-ebpf: reduce duplication ([`f35f7a3`](https://github.com/aya-rs/aya/commit/f35f7a3610d8296d97c6f0a47e75dbb4188f5212))
</details>

## v0.1.2 (2025-11-17)

<csr-id-1fe12b99907dda6553a6069fa462d6241d3fa171/>
<csr-id-5f5305c2a8ca0a739219093599dd57182d440ac1/>

### New Features

 - <csr-id-701a9333a828973f7bc5f8b7270b7936b0a4aaba/> , <csr-id-3ff60911375a6044bbf9060bef25aa5e9d3747ae/>, <csr-id-6252b4c9722c7c2ee2458741ae328dcc0c3c5234/> Regenerated the bindings from libbpf 324f3c38…, pulling in MIPS and LoongArch64 support alongside the latest kernel constants.
 - <csr-id-3ff609114e9be9ba029072bd9d86ef48beb03b9c/> Added MIPS bindings
   Updated `aya-obj/src/generated/mod.rs` and
   `bpf/aya-bpf-bindings/src/lib.rs to use the mips bindings.

### Maintenance

 - <csr-id-1fe12b99907dda6553a6069fa462d6241d3fa171/>, <csr-id-5f5305c2a8ca0a739219093599dd57182d440ac1/> General lint/build fixes (including the riscv64 build) to keep the generated code warning-free.

### Other

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
 - <csr-id-f610453ec234921c07aeb4d5401d0a8940d513df/> extract CARGO_CFG_BPF_TARGET_ARCH logic
 - <csr-id-fe99fa1d2eee94c4bf60d698784cae3c43f3a71c/> run clippy with target=bpf
   This build warnings from integration tests and makes `aya-ebpf`'s build
   script stricter.
 - <csr-id-49a828ec5655f6ecd0c38083c6c0dca217bad777/> reorder-keys
   Group non-workspace keys before workspace ones for readability.
 - <csr-id-6252b4c9722c7c2ee2458741ae328dcc0c3c5234/> hook up loongarch64
   This causes rustfmt to format those files.
   
   Squish some other conditional compilation to get rustfmt sorting.
 - <csr-id-56ebe1406e088dc52d7c796be725df74356fcad8/> do not attempt to run rustfmt
   This can be done externally. Do so in CI.
   
   This is an attempt to resolve the inconsistency between CI and local
   rustfmt in the generated bindings.
   
   Restore running CI on generated branches; the presence of a PR is
   apparently not enough.
 - <csr-id-c8f14b18d48fd4f92d97c89864d51a23fbe9d943/> tidy up
   Move some code out of a loop, where it appears to be nonsense.
 - <csr-id-b513af12e8baa5c5097eaf0afdae61a830c3f877/> add archs powerpc64 and s390x to aya
   bpfman, a project using aya, has a requirement to support powerpc64 and
   s390x architectures. Adding these two architectures to aya.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 30 commits contributed to the release.
 - 9 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 1 unique issue was worked on: [#1139](https://github.com/aya-rs/aya/issues/1139)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#1139](https://github.com/aya-rs/aya/issues/1139)**
    - Fix aya-ebpf-* riscv64 build ([`1fe12b9`](https://github.com/aya-rs/aya/commit/1fe12b99907dda6553a6069fa462d6241d3fa171))
 * **Uncategorized**
    - Release crates ([`d238b2e`](https://github.com/aya-rs/aya/commit/d238b2ea6f1b2c1aa09a9050415b1c96329af0aa))
    - Support hardware breakpoints ([`ab38afe`](https://github.com/aya-rs/aya/commit/ab38afe95d16226f5a703bbb37c7842ee441c364))
    - Extract CARGO_CFG_BPF_TARGET_ARCH logic ([`f610453`](https://github.com/aya-rs/aya/commit/f610453ec234921c07aeb4d5401d0a8940d513df))
    - Run clippy with target=bpf ([`fe99fa1`](https://github.com/aya-rs/aya/commit/fe99fa1d2eee94c4bf60d698784cae3c43f3a71c))
    - Lint all crates; enable strict pointer lints ([`5f5305c`](https://github.com/aya-rs/aya/commit/5f5305c2a8ca0a739219093599dd57182d440ac1))
    - Aya-obj, aya-ebpf-bindings: regenerate ([`bd0424c`](https://github.com/aya-rs/aya/commit/bd0424ca61a1c9ccd6e15e5a846c2915d067a7ea))
    - Reorder-keys ([`49a828e`](https://github.com/aya-rs/aya/commit/49a828ec5655f6ecd0c38083c6c0dca217bad777))
    - Introduce workspace lints, warn on unused crates ([`a43e40a`](https://github.com/aya-rs/aya/commit/a43e40ae1d1441ab4aea6a1a5d9ea36b56d62ff8))
    - Hook up loongarch64 ([`6252b4c`](https://github.com/aya-rs/aya/commit/6252b4c9722c7c2ee2458741ae328dcc0c3c5234))
    - Do not attempt to run rustfmt ([`56ebe14`](https://github.com/aya-rs/aya/commit/56ebe1406e088dc52d7c796be725df74356fcad8))
    - Aya-obj, aya-ebpf-bindings: regenerate ([`2bb2302`](https://github.com/aya-rs/aya/commit/2bb2302d1d59335516874a87e27a26f5c554004c))
    - Bump edition to 2024 ([`f0a9f19`](https://github.com/aya-rs/aya/commit/f0a9f19ddc7f02143a02dcc2bf6be88fa2d84063))
    - Use #[expect(...)] rather than #[allow(...)] ([`4101a5a`](https://github.com/aya-rs/aya/commit/4101a5a55d43cd9ead56497820c4d43018f74cbb))
    - Aya-obj, aya-ebpf-bindings: regenerate ([`ce0e93c`](https://github.com/aya-rs/aya/commit/ce0e93c75d4c0032d4766af3d4295bb9395f6876))
    - Aya-obj, aya-ebpf-bindings: regenerate ([`f49a761`](https://github.com/aya-rs/aya/commit/f49a761c2776709469901d1c9108f81247ca8d65))
    - Tidy up ([`c8f14b1`](https://github.com/aya-rs/aya/commit/c8f14b18d48fd4f92d97c89864d51a23fbe9d943))
    - Merge pull request #482 from ishanjain28/add_mips_support ([`2f757b2`](https://github.com/aya-rs/aya/commit/2f757b2091d28a17c90495ee2955e7f8d1bc5ec5))
    - Added MIPS bindings ([`3ff6091`](https://github.com/aya-rs/aya/commit/3ff609114e9be9ba029072bd9d86ef48beb03b9c))
    - Merge pull request #1155 from aya-rs/codegen ([`66da874`](https://github.com/aya-rs/aya/commit/66da8742feaf80d1e195e25f0cf715a8cc00012c))
    - [codegen] Update libbpf to 324f3c3846d99c8a1e1384a55591f893f0ae5de4 ([`701a933`](https://github.com/aya-rs/aya/commit/701a9333457ce008440350a9f465fe1f280c6069))
    - Release aya-ebpf-cty v0.2.2, aya-ebpf-bindings v0.1.1, aya-ebpf-macros v0.1.1, aya-ebpf v0.1.1 ([`59082f5`](https://github.com/aya-rs/aya/commit/59082f572c01e8356312ed53bdb818cfbea944b5))
    - Merge pull request #974 from Billy99/billy99-arch-ppc64-s390x ([`ab5e688`](https://github.com/aya-rs/aya/commit/ab5e688fd49fcfb402ad47d51cb445437fbd8cb7))
    - Add archs powerpc64 and s390x to aya ([`b513af1`](https://github.com/aya-rs/aya/commit/b513af12e8baa5c5097eaf0afdae61a830c3f877))
    - Merge pull request #1010 from aya-rs/codegen ([`bdbd042`](https://github.com/aya-rs/aya/commit/bdbd0423f8aa00f9e59a0b06d2ac9735c373c27f))
    - [codegen] Update libbpf to b07dfe3b2a6cb0905e883510f22f9f7c0bb66d0dUpdate libbpf to b07dfe3b2a6cb0905e883510f22f9f7c0bb66d0d ([`e217727`](https://github.com/aya-rs/aya/commit/e2177278ae9951a0262349a6741d013032b3cce6))
    - Merge pull request #978 from aya-rs/codegen ([`06aa5c8`](https://github.com/aya-rs/aya/commit/06aa5c8ed344bd0d85096a0fd033ff0bd90a2f88))
    - [codegen] Update libbpf to c1a6c770c46c6e78ad6755bf596c23a4e6f6b216 ([`8b50a6a`](https://github.com/aya-rs/aya/commit/8b50a6a5738b5a57121205490d26805c74cb63de))
    - Allowlist expected cfgs ([`e4f9ed8`](https://github.com/aya-rs/aya/commit/e4f9ed8d79e4cd19ab5124352fca9e6cbdc1030b))
    - Deny warnings ([`b603c66`](https://github.com/aya-rs/aya/commit/b603c665a9a2ec48de2c4b412876bd015e5ead15))
</details>

## v0.1.1 (2024-10-09)

<csr-id-b513af12e8baa5c5097eaf0afdae61a830c3f877/>

### Other

 - <csr-id-b513af12e8baa5c5097eaf0afdae61a830c3f877/> add archs powerpc64 and s390x to aya
   bpfman, a project using aya, has a requirement to support powerpc64 and
   s390x architectures. Adding these two architectures to aya.

## v0.1.0 (2024-04-06)

<csr-id-70ac91dc1e6f209a701cd868db215763d65efa73/>
<csr-id-b06ff402780b80862933791831c578e4c339fc96/>
<csr-id-c7fe60d47e0cc32fc7123e37532d104eaa392b50/>
<csr-id-a4ae8adb0db75f2b82b10b0740447a1dbead62c0/>

### Chore

 - <csr-id-70ac91dc1e6f209a701cd868db215763d65efa73/> Rename bpf -> ebpf

### Chore

 - <csr-id-a4ae8adb0db75f2b82b10b0740447a1dbead62c0/> add version keys to Cargo.toml(s)

### Chore

 - <csr-id-c7fe60d47e0cc32fc7123e37532d104eaa392b50/> add changelogs

### Other

 - <csr-id-b06ff402780b80862933791831c578e4c339fc96/> Generate new bindings

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 7 commits contributed to the release.
 - 4 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release aya-ebpf-bindings v0.1.0, aya-ebpf-macros v0.1.0, aya-ebpf v0.1.0 ([`a34c5e4`](https://github.com/aya-rs/aya/commit/a34c5e43b85dd176b9b18f1cc9c9d80d52f10a1f))
    - Add version keys to Cargo.toml(s) ([`a4ae8ad`](https://github.com/aya-rs/aya/commit/a4ae8adb0db75f2b82b10b0740447a1dbead62c0))
    - Release aya-ebpf-bindings v0.1.0, aya-ebpf-macros v0.1.0, aya-ebpf v0.1.0 ([`b8964d3`](https://github.com/aya-rs/aya/commit/b8964d3fd27353beb9054dd18fe8d16251f9164b))
    - Add changelogs ([`c7fe60d`](https://github.com/aya-rs/aya/commit/c7fe60d47e0cc32fc7123e37532d104eaa392b50))
    - Generate new bindings ([`b06ff40`](https://github.com/aya-rs/aya/commit/b06ff402780b80862933791831c578e4c339fc96))
    - Merge pull request #528 from dave-tucker/rename-all-the-things ([`63d8d4d`](https://github.com/aya-rs/aya/commit/63d8d4d34bdbbee149047dc0a5e9c2b191f3b32d))
    - Rename bpf -> ebpf ([`70ac91d`](https://github.com/aya-rs/aya/commit/70ac91dc1e6f209a701cd868db215763d65efa73))
</details>

