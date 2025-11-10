# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

