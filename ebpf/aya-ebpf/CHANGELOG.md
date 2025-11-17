# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes

 - <csr-id-3569c9afc3dc7babb6b44aa071828df7c8864834/> Map helper functions now take `*mut c_void`, matching the kernel’s prototypes. Any out-of-tree helpers should update their signatures accordingly.

### New Features

 - <csr-id-0b58d3eb6d399c812181d2d64de32cde1b44f6eb/> Added a `bpf_strncmp` helper binding.
 - <csr-id-f34d355d7d70f8f9ef0f0a01a4338e50cf0080b4/> Raw tracepoints now expose their arguments so programs no longer need to guess register layouts.
 - <csr-id-1ccac3c135f280eead50ff18cd4c4340001018c6/>, <csr-id-6252b4c9722c7c2ee2458741ae328dcc0c3c5234/> Added mips/loongarch register helpers so those targets can implement `FromPtRegs`.
 - <csr-id-dc543ae44aab09ea9ab550b164ca0711293e87fe/> `XdpContext` exposes the interface index, simplifying multi-interface programs.
 - <csr-id-2fb19f3ee2c95a34382b33762e9fb8841ec8c048/> Added `Array::set()` to update array contents from eBPF code.
 - <csr-id-77b1c6194c8f9bb69ffc6a60c3b8189b73e00e8f/> Introduced Flow Dissector program support on the eBPF side.
 - <csr-id-3f60168d4bab042d26094f7962b96f0772b52ae7/> Added `RingBufBytes` so probes can emit raw byte slices efficiently.
 - <csr-id-0b2a544ddd9df74ebcdb46128b6bcc48336b2762/>, <csr-id-53ec6164114bba84be145dc9659aaac917dd7a15/> Added BTF array definitions plus `Queue`/`Stack::peek()` helpers for safer data-structure inspection.

### Bug Fixes

 - <csr-id-1fe12b99907dda6553a6069fa462d6241d3fa171/> Fixed riscv64 builds by updating the generated bindings.
 - <csr-id-f537dc66845e70bc3af2dbb9944562cf38117bcb/> Cleaned up ring-buffer code to avoid reliance on `as` casts, preventing UB on strict architectures.
 - <csr-id-6004fcdb0fb5a6157ba5416f439e5807567c87a7/> Guarded the libc `mem*` shims behind `cfg(target_arch = "bpf")`, ensuring CPU builds stay well-defined.

### Maintenance

 - <csr-id-4f654865e9e592a93e11feb8558a461c4b6865b5/>, <csr-id-4b4b9f83bd6c1762a5366d2d89353adf4364f76e/> Added configuration flags for `generic_const_exprs` and the loongarch target, plus the usual lint/documentation refresh.

## v0.1.1 (2024-10-09)

### New Features

 - <csr-id-7ad3926d996f6471da05a8f3cab0283bb38c1498/> Implement memmove
   The compiler will emit this function for certain operations, but aya
   currently does not provide an implementation.
   This leads to ebpf loading failures as the kernel can't find the symbol when
   loading the program.
   
   The implementation is based on https://github.com/rust-lang/compiler-builtins/blob/master/src/mem/mod.rs#L29-L40
   and https://github.com/rust-lang/compiler-builtins/blob/master/src/mem/impls.rs#L128-L135
   Only the simplest case has been implemented, none of the word optimizations,
   since memcpy also doesn't seem to have them.

### Bug Fixes

 - <csr-id-ef0d1253efcc5a385afc74668d4f28580d328822/> Remove PerfEventArray::with_max_entries
   This API doesn't make sense as the max_entries needs to be set to the
   number of online CPUs by the loader.

### Other

 - <csr-id-95e1763e30e0dcfe1256ecd9e32ca27dd65342b4/> Add set_reply accessor to SockOpsContext
 - <csr-id-b513af12e8baa5c5097eaf0afdae61a830c3f877/> add archs powerpc64 and s390x to aya
   bpfman, a project using aya, has a requirement to support powerpc64 and
   s390x architectures. Adding these two architectures to aya.
 - <csr-id-2d38b23b99cd259f7a249f4c63b12da909c67015/> moved ret from ProbeContext into new RetProbeContext
   Created retprobe.rs to hold RetProbeContext and moved the ret from
   ProbeContext in probe.rs into RetProbeContext. Now, only kprobe (which
   uses ProbeContext) can access args, and kretprobe (which uses
   RetProbeContext) can access ret.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 11 commits contributed to the release.
 - 185 days passed between releases.
 - 5 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Merge pull request #1020 from l2dy/sockops-ctx ([`635ed3b`](https://github.com/aya-rs/aya/commit/635ed3baed5442c1364a360d7234b72c4ffe3fd8))
    - Add set_reply accessor to SockOpsContext ([`95e1763`](https://github.com/aya-rs/aya/commit/95e1763e30e0dcfe1256ecd9e32ca27dd65342b4))
    - Merge pull request #974 from Billy99/billy99-arch-ppc64-s390x ([`ab5e688`](https://github.com/aya-rs/aya/commit/ab5e688fd49fcfb402ad47d51cb445437fbd8cb7))
    - Add archs powerpc64 and s390x to aya ([`b513af1`](https://github.com/aya-rs/aya/commit/b513af12e8baa5c5097eaf0afdae61a830c3f877))
    - Appease nightly clippy ([`bce3c4f`](https://github.com/aya-rs/aya/commit/bce3c4fb1d0cd6e8f9f64420c59e02a42c96b2c8))
    - Remove PerfEventArray::with_max_entries ([`ef0d125`](https://github.com/aya-rs/aya/commit/ef0d1253efcc5a385afc74668d4f28580d328822))
    - Implement memmove ([`7ad3926`](https://github.com/aya-rs/aya/commit/7ad3926d996f6471da05a8f3cab0283bb38c1498))
    - Allowlist expected cfgs ([`e4f9ed8`](https://github.com/aya-rs/aya/commit/e4f9ed8d79e4cd19ab5124352fca9e6cbdc1030b))
    - Deny warnings ([`b603c66`](https://github.com/aya-rs/aya/commit/b603c665a9a2ec48de2c4b412876bd015e5ead15))
    - Moved ret from ProbeContext into new RetProbeContext ([`2d38b23`](https://github.com/aya-rs/aya/commit/2d38b23b99cd259f7a249f4c63b12da909c67015))
    - Appease clippy ([`57cd351`](https://github.com/aya-rs/aya/commit/57cd35172f1534444a548460de6eae4680488711))
</details>

## v0.1.0 (2024-04-06)

<csr-id-d7af6acb42055ed1e0571bdc4d7dbbfa46c5835e/>
<csr-id-ea8073793e44c593e983e69eaa43a4f72799bfc5/>
<csr-id-41c61560eae01a30c703ea22c5bfeeff0ecf6b1b/>
<csr-id-c7fe60d47e0cc32fc7123e37532d104eaa392b50/>
<csr-id-a4ae8adb0db75f2b82b10b0740447a1dbead62c0/>

### Chore

 - <csr-id-d7af6acb42055ed1e0571bdc4d7dbbfa46c5835e/> Rename BpfContext -> EbpfContext
 - <csr-id-ea8073793e44c593e983e69eaa43a4f72799bfc5/> Rename bpf -> ebpf
 - <csr-id-41c61560eae01a30c703ea22c5bfeeff0ecf6b1b/> Rename bpf -> ebpf

### Chore

 - <csr-id-a4ae8adb0db75f2b82b10b0740447a1dbead62c0/> add version keys to Cargo.toml(s)

### Chore

 - <csr-id-c7fe60d47e0cc32fc7123e37532d104eaa392b50/> add changelogs

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 10 commits contributed to the release.
 - 5 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release aya-ebpf v0.1.0 ([`c3ae6f9`](https://github.com/aya-rs/aya/commit/c3ae6f90d8d3be8b31d1de9ccc042133f9ac8f44))
    - Release aya-ebpf-macros v0.1.0, aya-ebpf v0.1.0 ([`eb3947b`](https://github.com/aya-rs/aya/commit/eb3947bf14e8e7ab0f70e12306e38fb8056edf57))
    - Release aya-ebpf-bindings v0.1.0, aya-ebpf-macros v0.1.0, aya-ebpf v0.1.0 ([`a34c5e4`](https://github.com/aya-rs/aya/commit/a34c5e43b85dd176b9b18f1cc9c9d80d52f10a1f))
    - Add version keys to Cargo.toml(s) ([`a4ae8ad`](https://github.com/aya-rs/aya/commit/a4ae8adb0db75f2b82b10b0740447a1dbead62c0))
    - Release aya-ebpf-bindings v0.1.0, aya-ebpf-macros v0.1.0, aya-ebpf v0.1.0 ([`b8964d3`](https://github.com/aya-rs/aya/commit/b8964d3fd27353beb9054dd18fe8d16251f9164b))
    - Add changelogs ([`c7fe60d`](https://github.com/aya-rs/aya/commit/c7fe60d47e0cc32fc7123e37532d104eaa392b50))
    - Merge pull request #528 from dave-tucker/rename-all-the-things ([`63d8d4d`](https://github.com/aya-rs/aya/commit/63d8d4d34bdbbee149047dc0a5e9c2b191f3b32d))
    - Rename BpfContext -> EbpfContext ([`d7af6ac`](https://github.com/aya-rs/aya/commit/d7af6acb42055ed1e0571bdc4d7dbbfa46c5835e))
    - Rename bpf -> ebpf ([`ea80737`](https://github.com/aya-rs/aya/commit/ea8073793e44c593e983e69eaa43a4f72799bfc5))
    - Rename bpf -> ebpf ([`41c6156`](https://github.com/aya-rs/aya/commit/41c61560eae01a30c703ea22c5bfeeff0ecf6b1b))
</details>

