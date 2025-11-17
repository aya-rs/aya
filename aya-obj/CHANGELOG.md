# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### New Features

 - <csr-id-77b1c6194c8f9bb69ffc6a60c3b8189b73e00e8f/> Updated the loader to understand Flow Dissector programs so objects containing those sections can now be parsed and attached.
 - <csr-id-3ff60911375a6044bbf9060bef25aa5e9d3747ae/>, <csr-id-6252b4c9722c7c2ee2458741ae328dcc0c3c5234/> Regenerated libbpf bindings, bringing in MIPS and LoongArch64 support.
 - <csr-id-94c85726b3860787152b0ab9929f3d69f777e7a3/>, <csr-id-658ae0fbd27b481780dc8df0c9ff4021777fe94c/> Switched to generated constants and helper APIs (e.g. `CStr::from_bytes_until_nul`) for safer symbol handling.

### Bug Fixes

 - <csr-id-7224efcad8726439e9ac9ccdc28e19116bf00606/>, <csr-id-8e9404ec3cc0564cafad6a733cb138ed1421d462/> Fixed BTF relocations involving zero-sized sections and 64-bit enums so objects built with newer clang/jit toolchains load correctly.
 - <csr-id-3ade19b869dd3aa746d17e52bb3c7b683859e413/>, <csr-id-f76fdf9da51852f5e13011b2d3ba6f9204943de7/> Promoted BTF loading failures (and diagnostic output) to proper errors instead of panics/unreachable paths.

### Maintenance

 - <csr-id-23bc5b5836c3b8383f2f8a78bd3902e193a7a176/>, <csr-id-9a47495227a03400fa2549b07fe8af131f21e759/> Cached feature-probed info fields and preserved pointer provenance, plus the usual lint/edition updates to stay aligned with the workspace.

## 0.2.1 (2024-11-01)

### New Features

 - <csr-id-8c79b71bd5699a686f33360520aa95c1a2895fa5/> Rename Bpf to Ebpf
   And BpfLoader to EbpfLoader.
   This also adds type aliases to preserve the use of the old names, making
   updating to a new Aya release less of a burden. These aliases are marked
   as deprecated since we'll likely remove them in a later release.

### Bug Fixes

 - <csr-id-ca0c32d1076af81349a52235a4b6fb3937a697b3/> Fill bss maps with zeros
   The loader should fill bss maps with zeros according to the size of the
   ELF section.
   Failure to do so yields weird verifier messages as follows:
   
   ```
   cannot access ptr member ops with moff 0 in struct bpf_map with off 0 size 4
   ```
   
   Reference to this in the cilium/ebpf code is here [1].
   I could not find a reference in libbpf.

### Other

 - <csr-id-366c599c2083baf72c40c816da2c530dec7fd612/> cgroup_iter_order NFPROTO* nf_inet_hooks
   Adds the following to codegen:
   - `bpf_cgroup_iter_order`: used in `bpf_link_info.iter.group.order`
   - `NFPROTO_*`: used in `bpf_link_info.netfilter.pf`
   - `nf_inet_hooks`: used in `bpf_link_info.netfilter.hooknum`
   
   Include `linux/netfilter.h` in `linux_wrapper.h` for `NFPROTO_*` and
   `nf_inet_hooks` to generate.
 - <csr-id-fbb09304a2de0d8baf7ea20c9727fcd2e4fb7f41/> revamp MapInfo be more friendly with older kernels
   Adds detection for whether a field is available in `MapInfo`:
   - For `map_type()`, we treturn new enum `MapType` instead of the integer
     representation.
   - For fields that can't be zero, we return `Option<NonZero*>` type.
   - For `name_as_str()`, it now uses the feature probe `bpf_name()` to
     detect if field is available.
     Although the feature probe checks for program name, it can also be
     used for map name since they were both introduced in the same commit.
 - <csr-id-88f5ac31142f1657b41b1ee0f217dcd9125b210a/> revamp ProgramInfo be more friendly with older kernels
   Purpose of this commit is to add detections for whether a field is
   available in `ProgramInfo`.
   - For `program_type()`, we return the new enum `ProgramType` instead of
     the integer representation.
   - For fields that we know cannot be zero, we return `Option<NonZero*>`
     type.
   - For `name_as_str()`, it now also uses the feature probe `bpf_name()`
     to detect if field is available or not.
   - Two additional feature probes are added for the fields:
     - `prog_info_map_ids()` probe -> `map_ids()` field
     - `prog_info_gpl_compatible()` probe -> `gpl_compatible()` field
   
   With the `prog_info_map_ids()` probe, the previous implementation that
   I had for `bpf_prog_get_info_by_fd()` is shortened to use the probe
   instead of having to make 2 potential syscalls.
   
   The `test_loaded_at()` test is also moved into info tests since it is
   better related to the info tests.
 - <csr-id-1634fa7188e40ed75da53517f1fdb7396c348c34/> add conversion u32 to enum type for prog, link, & attach type
   Add conversion from u32 to program type, link type, and attach type.
   Additionally, remove duplicate match statement for u32 conversion to
   `BPF_MAP_TYPE_BLOOM_FILTER` & `BPF_MAP_TYPE_CGRP_STORAGE`.
   
   New error `InvalidTypeBinding<T>` is created to represent when a
   parsed/received value binding to a type is invalid.
   This is used in the new conversions added here, and also replaces
   `InvalidMapTypeError` in `TryFrom` for `bpf_map_type`.
 - <csr-id-b513af12e8baa5c5097eaf0afdae61a830c3f877/> add archs powerpc64 and s390x to aya
   bpfman, a project using aya, has a requirement to support powerpc64 and
   s390x architectures. Adding these two architectures to aya.
 - <csr-id-b06ff402780b80862933791831c578e4c339fc96/> Generate new bindings

### Test

 - <csr-id-4dc4b5ccd48bd86e2cc59ad7386514c1531450af/> adjust test to not use byte arrays
   Where possible, replace the hardcoded byte arrays in the tests with the
   structs they represent, then convert the structs to byte arrays.
 - <csr-id-eef7346fb2231f8741410381198015cceeebfac9/> adjust test byte arrays for big endian
   Adding support for s390x (big endian architecture) and found that some
   of the unit tests have structures and files implemented as byte arrays.
   They are all coded as little endian and need a bug endian version to
   work properly.

### New Features (BREAKING)

 - <csr-id-fd48c55466a23953ce7a4912306e1acf059b498b/> Rename BpfRelocationError -> EbpfRelocationError
 - <csr-id-cf3e2ca677c81224368fb2838ebc5b10ee98419a/> Rename BpfSectionKind to EbpfSectionKind

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 25 commits contributed to the release over the course of 241 calendar days.
 - 247 days passed between releases.
 - 12 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Merge pull request #1073 from dave-tucker/reloc-bug ([`b2ac9fe`](https://github.com/aya-rs/aya/commit/b2ac9fe85db6c25d0b8155a75a2df96a80a19811))
    - Fill bss maps with zeros ([`ca0c32d`](https://github.com/aya-rs/aya/commit/ca0c32d1076af81349a52235a4b6fb3937a697b3))
    - Merge pull request #1055 from aya-rs/codegen ([`59b3873`](https://github.com/aya-rs/aya/commit/59b3873a92d1eb49ca1008cb193e962fa95b3e97))
    - [codegen] Update libbpf to 80b16457cb23db4d633b17ba0305f29daa2eb307 ([`f8ad84c`](https://github.com/aya-rs/aya/commit/f8ad84c3d322d414f27375044ba694a169abfa76))
    - Cgroup_iter_order NFPROTO* nf_inet_hooks ([`366c599`](https://github.com/aya-rs/aya/commit/366c599c2083baf72c40c816da2c530dec7fd612))
    - Release aya-obj v0.2.0, aya v0.13.0, safety bump aya v0.13.0 ([`c169b72`](https://github.com/aya-rs/aya/commit/c169b727e6b8f8c2dda57f54b8c77f8b551025c6))
    - Appease clippy ([`aa240ba`](https://github.com/aya-rs/aya/commit/aa240baadf99d3fea0477a9b3966789b0f4ffe57))
    - Merge pull request #1007 from tyrone-wu/aya/info-api ([`15eb935`](https://github.com/aya-rs/aya/commit/15eb935bce6d41fb67189c48ce582b074544e0ed))
    - Revamp MapInfo be more friendly with older kernels ([`fbb0930`](https://github.com/aya-rs/aya/commit/fbb09304a2de0d8baf7ea20c9727fcd2e4fb7f41))
    - Revamp ProgramInfo be more friendly with older kernels ([`88f5ac3`](https://github.com/aya-rs/aya/commit/88f5ac31142f1657b41b1ee0f217dcd9125b210a))
    - Add conversion u32 to enum type for prog, link, & attach type ([`1634fa7`](https://github.com/aya-rs/aya/commit/1634fa7188e40ed75da53517f1fdb7396c348c34))
    - Merge pull request #974 from Billy99/billy99-arch-ppc64-s390x ([`ab5e688`](https://github.com/aya-rs/aya/commit/ab5e688fd49fcfb402ad47d51cb445437fbd8cb7))
    - Adjust test to not use byte arrays ([`4dc4b5c`](https://github.com/aya-rs/aya/commit/4dc4b5ccd48bd86e2cc59ad7386514c1531450af))
    - Add archs powerpc64 and s390x to aya ([`b513af1`](https://github.com/aya-rs/aya/commit/b513af12e8baa5c5097eaf0afdae61a830c3f877))
    - Adjust test byte arrays for big endian ([`eef7346`](https://github.com/aya-rs/aya/commit/eef7346fb2231f8741410381198015cceeebfac9))
    - Merge pull request #989 from aya-rs/codegen ([`8015e10`](https://github.com/aya-rs/aya/commit/8015e100796c550804ccf8fea691c63ec1ac36b8))
    - [codegen] Update libbpf to 686f600bca59e107af4040d0838ca2b02c14ff50 ([`8d7446e`](https://github.com/aya-rs/aya/commit/8d7446e01132fe1751605b87a6b4a0165273de15))
    - Merge pull request #978 from aya-rs/codegen ([`06aa5c8`](https://github.com/aya-rs/aya/commit/06aa5c8ed344bd0d85096a0fd033ff0bd90a2f88))
    - [codegen] Update libbpf to c1a6c770c46c6e78ad6755bf596c23a4e6f6b216 ([`8b50a6a`](https://github.com/aya-rs/aya/commit/8b50a6a5738b5a57121205490d26805c74cb63de))
    - Document miri skip reasons ([`35962a4`](https://github.com/aya-rs/aya/commit/35962a4794484aa3b37dadc98a70a659fd107b75))
    - Generate new bindings ([`b06ff40`](https://github.com/aya-rs/aya/commit/b06ff402780b80862933791831c578e4c339fc96))
    - Merge pull request #528 from dave-tucker/rename-all-the-things ([`63d8d4d`](https://github.com/aya-rs/aya/commit/63d8d4d34bdbbee149047dc0a5e9c2b191f3b32d))
    - Rename Bpf to Ebpf ([`8c79b71`](https://github.com/aya-rs/aya/commit/8c79b71bd5699a686f33360520aa95c1a2895fa5))
    - Rename BpfRelocationError -> EbpfRelocationError ([`fd48c55`](https://github.com/aya-rs/aya/commit/fd48c55466a23953ce7a4912306e1acf059b498b))
    - Rename BpfSectionKind to EbpfSectionKind ([`cf3e2ca`](https://github.com/aya-rs/aya/commit/cf3e2ca677c81224368fb2838ebc5b10ee98419a))
</details>

## 0.2.0 (2024-10-09)

<csr-id-fbb09304a2de0d8baf7ea20c9727fcd2e4fb7f41/>
<csr-id-88f5ac31142f1657b41b1ee0f217dcd9125b210a/>
<csr-id-1634fa7188e40ed75da53517f1fdb7396c348c34/>
<csr-id-b513af12e8baa5c5097eaf0afdae61a830c3f877/>
<csr-id-b06ff402780b80862933791831c578e4c339fc96/>
<csr-id-4dc4b5ccd48bd86e2cc59ad7386514c1531450af/>
<csr-id-eef7346fb2231f8741410381198015cceeebfac9/>

### New Features

 - <csr-id-8c79b71bd5699a686f33360520aa95c1a2895fa5/> Rename Bpf to Ebpf
   And BpfLoader to EbpfLoader.
   This also adds type aliases to preserve the use of the old names, making
   updating to a new Aya release less of a burden. These aliases are marked
   as deprecated since we'll likely remove them in a later release.

### Other

 - <csr-id-fbb09304a2de0d8baf7ea20c9727fcd2e4fb7f41/> revamp MapInfo be more friendly with older kernels
   Adds detection for whether a field is available in `MapInfo`:
   - For `map_type()`, we treturn new enum `MapType` instead of the integer
     representation.
   - For fields that can't be zero, we return `Option<NonZero*>` type.
   - For `name_as_str()`, it now uses the feature probe `bpf_name()` to
     detect if field is available.
     Although the feature probe checks for program name, it can also be
     used for map name since they were both introduced in the same commit.
 - <csr-id-88f5ac31142f1657b41b1ee0f217dcd9125b210a/> revamp ProgramInfo be more friendly with older kernels
   Purpose of this commit is to add detections for whether a field is
   available in `ProgramInfo`.
   - For `program_type()`, we return the new enum `ProgramType` instead of
     the integer representation.
   - For fields that we know cannot be zero, we return `Option<NonZero*>`
     type.
   - For `name_as_str()`, it now also uses the feature probe `bpf_name()`
     to detect if field is available or not.
   - Two additional feature probes are added for the fields:
     - `prog_info_map_ids()` probe -> `map_ids()` field
     - `prog_info_gpl_compatible()` probe -> `gpl_compatible()` field
   
   With the `prog_info_map_ids()` probe, the previous implementation that
   I had for `bpf_prog_get_info_by_fd()` is shortened to use the probe
   instead of having to make 2 potential syscalls.
   
   The `test_loaded_at()` test is also moved into info tests since it is
   better related to the info tests.
 - <csr-id-1634fa7188e40ed75da53517f1fdb7396c348c34/> add conversion u32 to enum type for prog, link, & attach type
   Add conversion from u32 to program type, link type, and attach type.
   Additionally, remove duplicate match statement for u32 conversion to
   `BPF_MAP_TYPE_BLOOM_FILTER` & `BPF_MAP_TYPE_CGRP_STORAGE`.
   
   New error `InvalidTypeBinding<T>` is created to represent when a
   parsed/received value binding to a type is invalid.
   This is used in the new conversions added here, and also replaces
   `InvalidMapTypeError` in `TryFrom` for `bpf_map_type`.
 - <csr-id-b513af12e8baa5c5097eaf0afdae61a830c3f877/> add archs powerpc64 and s390x to aya
   bpfman, a project using aya, has a requirement to support powerpc64 and
   s390x architectures. Adding these two architectures to aya.
 - <csr-id-b06ff402780b80862933791831c578e4c339fc96/> Generate new bindings

### Test

 - <csr-id-4dc4b5ccd48bd86e2cc59ad7386514c1531450af/> adjust test to not use byte arrays
   Where possible, replace the hardcoded byte arrays in the tests with the
   structs they represent, then convert the structs to byte arrays.
 - <csr-id-eef7346fb2231f8741410381198015cceeebfac9/> adjust test byte arrays for big endian
   Adding support for s390x (big endian architecture) and found that some
   of the unit tests have structures and files implemented as byte arrays.
   They are all coded as little endian and need a bug endian version to
   work properly.

### New Features (BREAKING)

 - <csr-id-fd48c55466a23953ce7a4912306e1acf059b498b/> Rename BpfRelocationError -> EbpfRelocationError
 - <csr-id-cf3e2ca677c81224368fb2838ebc5b10ee98419a/> Rename BpfSectionKind to EbpfSectionKind

## 0.1.0 (2024-02-28)

<csr-id-b3e7ef741c5b8d09fc7dc8302576f8174be75ff4/>
<csr-id-770a95e0779a6a943c2f5439334fa208ac2ca7e6/>
<csr-id-3369169aaca6510a47318fc29bbdb801b60b1c21/>
<csr-id-c05a3b69b7a94036c380bd64c6de51377987077c/>
<csr-id-35e21ae0079d38e90d90fc85d29580c8b44b16d4/>
<csr-id-cc48523347c2be5520779ef8eeadc6d3a68649d0/>
<csr-id-d16e607fd4b6258b516913071fdacafeb2bbbff9/>
<csr-id-00dc7a5bd4468b7d86d7f167a49e78d89016e2ac/>
<csr-id-139f3826383daba9a10dc7aacc079f31d28980fc/>
<csr-id-f41592663cda156082255b93db145cfdd19378e5/>
<csr-id-c139627f8f180638b786b5e3cd48b8473d96fe56/>
<csr-id-89bc255f1d14d72a61064b9b40b641b58f8970e0/>
<csr-id-02124002c88d7a89d6c9afd89857c4c301e09801/>
<csr-id-dfb6020a1dc1d0ee28426bd9e3086dd449f643f7/>
<csr-id-098d4364bd0fb8551f0515cb84afda6aff23ed7f/>
<csr-id-826e0e5050e9bf9e0cdff6d2a20c1169820d0e57/>
<csr-id-2a054d76ae167e7c2a6b4bfb1cf51770f93d394a/>
<csr-id-79ea64ca7fd3cc1b17573b539fd8fa8e76644beb/>
<csr-id-cca9b8f1a7e345a39d852bd18a43974871d3ed4b/>
<csr-id-677e7bda4a826aca858311670d1592162b682dff/>
<csr-id-bf7fdff1cef28961f096d1c1e00181e0a0c2d14e/>
<csr-id-17f25a67934ad10443a4fbb62a563b5f6edcaa5f/>
<csr-id-96fa08bd82233268154edf30b106876f5a4f0e30/>
<csr-id-6f2a8c8a5c47098fb5e5a75ecebdff493d486c97/>
<csr-id-d71d1e199382379036dc4760e4edbd5e637e07c3/>
<csr-id-27120b328aac5f992eed98b03216a9880a381749/>
<csr-id-d9dfd94f29be8c28b7fe0ef4ab560db49f7514fb/>
<csr-id-47f764c19185a69a00f3925239797caa98cd5afe/>
<csr-id-93435fc85400aa036f3890c43c78c9c9eb4baa96/>
<csr-id-f5f8083441afd2daed9344fc2031878d574efaf1/>
<csr-id-fa3dd4bef252566aa26577a0d42b2ff59ac2ff2a/>
<csr-id-35eaa50736d9e894eb5122b1070afd7b0442eae6/>
<csr-id-c4e721f3d334a7c2e5e6d6cd6f4ade0f1334be72/>
<csr-id-591e21267a9bc9adca9818095de5a695cee7ee9b/>
<csr-id-18b3d75d096e3c90f8c5b2f7292637a3369f96a6/>
<csr-id-9e1109b3ce70a3668771bd11a7fda101eec3ab93/>
<csr-id-4c78f7f1a014cf54d54c805233a0f29eb1ca5eeb/>
<csr-id-33a0a2b604e77b63b771b9d0e167c894793492b5/>
<csr-id-1132b6e01b86856aa1fddf179fcc7e3825e79406/>
<csr-id-4e33fa011e87cdc2fc59025b9e531b4872651cd0/>
<csr-id-93ac3e94bcb47864670c124dfe00e16ed2ab6f5e/>
<csr-id-b25a08981986cac4f511433d165560576a8c9856/>
<csr-id-5c4f1d69a60e0c5324512a7cfbc4467b7f5d0bca/>
<csr-id-dfbe1207c1bbd105d1daa9b08cec0e9803b5464e/>
<csr-id-7479c1dd6c1356bddb0401dbeea65618674524c9/>
<csr-id-ce22ca668f3e7c0f9832d28370457204537d2e50/>
<csr-id-376c48640033fdbf8b5199641f353587273f8a32/>
<csr-id-a18693b42dc986bde06b07540e261ecac59eef24/>
<csr-id-9a6f8143a1a4c5c88a373701d74d96596c75242f/>
<csr-id-4482db42d86c657826efe80f484f57a601ed2f38/>
<csr-id-d6b976c6f1f6163680c179502f4f454d0cec747e/>
<csr-id-3d03c8a8e0a9033be8c1ab020129db7790cc7493/>
<csr-id-cb28533e2f9eb0b2cd80f4bf9515cdec31763749/>
<csr-id-9c451a3357317405dd8e2e4df7d006cee943adcc/>
<csr-id-772af170aea2feccb5e98cc84125e9e31b9fbe9a/>
<csr-id-9ec3447e891ca770a65f8ff9b71884f25530f515/>
<csr-id-30f1fabc05654e8d11dd2648767895123c141c3b/>
<csr-id-311ead6760ce53e9503af00391e6631f7387ab4a/>
<csr-id-e52497cb9c02123ae450ca36fb6f898d24b25c4b/>
<csr-id-ac49827e204801079be2b87160a795ef412bd6cb/>
<csr-id-81bc307dce452f0aacbfbe8c304089d11ddd8c5e/>
<csr-id-572d047e37111b732be49ef3ad6fb16f70aa4063/>

### Chore

 - <csr-id-b3e7ef741c5b8d09fc7dc8302576f8174be75ff4/> Use the cargo workspace package table
   This allows for inheritance of common fields from the workspace root.
   The following fields have been made common:
   
   - authors
   - license
   - repository
   - homepage
   - edition
 - <csr-id-770a95e0779a6a943c2f5439334fa208ac2ca7e6/> Appease clippy unused imports

### Documentation

 - <csr-id-72e8aab6c8be8663c5b6ff6b606a51debf512f7d/> Add CHANGELOG

### Other

 - <csr-id-3369169aaca6510a47318fc29bbdb801b60b1c21/> appease new nightly clippy lints
   ```
     error: unnecessary use of `get("foo").is_some()`
         --> aya-obj/src/obj.rs:1690:26
          |
     1690 |         assert!(obj.maps.get("foo").is_some());
          |                          ^^^^^^^^^^^^^^^^^^^^ help: replace it with: `contains_key("foo")`
          |
          = help: for further information visit https://rust-lang.github.io/rust-clippy/master/index.html#unnecessary_get_then_check
     note: the lint level is defined here
         --> aya-obj/src/lib.rs:68:9
          |
     68   | #![deny(clippy::all, missing_docs)]
          |         ^^^^^^^^^^^
          = note: `#[deny(clippy::unnecessary_get_then_check)]` implied by `#[deny(clippy::all)]`
   
     error: unnecessary use of `get("foo").is_some()`
         --> aya-obj/src/obj.rs:1777:26
          |
     1777 |         assert!(obj.maps.get("foo").is_some());
          |                          ^^^^^^^^^^^^^^^^^^^^ help: replace it with: `contains_key("foo")`
          |
          = help: for further information visit https://rust-lang.github.io/rust-clippy/master/index.html#unnecessary_get_then_check
   
     error: unnecessary use of `get("bar").is_some()`
         --> aya-obj/src/obj.rs:1778:26
          |
     1778 |         assert!(obj.maps.get("bar").is_some());
          |                          ^^^^^^^^^^^^^^^^^^^^ help: replace it with: `contains_key("bar")`
          |
          = help: for further information visit https://rust-lang.github.io/rust-clippy/master/index.html#unnecessary_get_then_check
   
     error: unnecessary use of `get("baz").is_some()`
         --> aya-obj/src/obj.rs:1779:26
          |
     1779 |         assert!(obj.maps.get("baz").is_some());
          |                          ^^^^^^^^^^^^^^^^^^^^ help: replace it with: `contains_key("baz")`
          |
          = help: for further information visit https://rust-lang.github.io/rust-clippy/master/index.html#unnecessary_get_then_check
   
     error: unnecessary use of `get(".bss").is_some()`
         --> aya-obj/src/obj.rs:1799:26
          |
     1799 |         assert!(obj.maps.get(".bss").is_some());
          |                          ^^^^^^^^^^^^^^^^^^^^^ help: replace it with: `contains_key(".bss")`
          |
          = help: for further information visit https://rust-lang.github.io/rust-clippy/master/index.html#unnecessary_get_then_check
   
     error: unnecessary use of `get(".rodata").is_some()`
         --> aya-obj/src/obj.rs:1810:26
          |
     1810 |         assert!(obj.maps.get(".rodata").is_some());
          |                          ^^^^^^^^^^^^^^^^^^^^^^^^ help: replace it with: `contains_key(".rodata")`
          |
          = help: for further information visit https://rust-lang.github.io/rust-clippy/master/index.html#unnecessary_get_then_check
   
     error: unnecessary use of `get(".rodata.boo").is_some()`
         --> aya-obj/src/obj.rs:1821:26
          |
     1821 |         assert!(obj.maps.get(".rodata.boo").is_some());
          |                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ help: replace it with: `contains_key(".rodata.boo")`
          |
          = help: for further information visit https://rust-lang.github.io/rust-clippy/master/index.html#unnecessary_get_then_check
   
     error: unnecessary use of `get(".data").is_some()`
         --> aya-obj/src/obj.rs:1832:26
          |
     1832 |         assert!(obj.maps.get(".data").is_some());
          |                          ^^^^^^^^^^^^^^^^^^^^^^ help: replace it with: `contains_key(".data")`
          |
          = help: for further information visit https://rust-lang.github.io/rust-clippy/master/index.html#unnecessary_get_then_check
   
     error: unnecessary use of `get(".data.boo").is_some()`
         --> aya-obj/src/obj.rs:1843:26
          |
     1843 |         assert!(obj.maps.get(".data.boo").is_some());
          |                          ^^^^^^^^^^^^^^^^^^^^^^^^^^ help: replace it with: `contains_key(".data.boo")`
   ```
 - <csr-id-c05a3b69b7a94036c380bd64c6de51377987077c/> Handle lack of match of enum variants correctly
   When comparing `local_spec` with `target_spec` for enum relocations,
   we can encounter a situation when a matchinng variant in a candidate
   spec doesn't exist.
   
   Before this change, such case wasn't handled explicitly, therefore
   resulted in returning currently constructed `target_spec` at the
   end. The problem is that such `target_spec` was, due to lack of
   match, incomplete. It didn't contain any `accessors` nor `parts`.
   
   Later usage of such incomplete `target_spec` was leading to panics,
   since the code operating on enums' `target_spec` expects at least
   one `accessor` to be available.
 - <csr-id-35e21ae0079d38e90d90fc85d29580c8b44b16d4/> don't parse labels as programs
   Fixes a bug introduced by https://github.com/aya-rs/aya/pull/413 where
   we were generating a bunch of spurious LBB* programs.
 - <csr-id-cc48523347c2be5520779ef8eeadc6d3a68649d0/> remove redundant keys
   `default-features = false` is already in the root Cargo.toml.
 - <csr-id-d16e607fd4b6258b516913071fdacafeb2bbbff9/> group_imports = "StdExternalCrate"
   High time we stop debating this; let the robots do the work.
 - <csr-id-00dc7a5bd4468b7d86d7f167a49e78d89016e2ac/> make maps work on kernels not supporting ProgIds
   On startup, the kernel is probed for support of chained program ids for
   CpuMap, DevMap and DevMapHash, and will patch maps at load time to have
   the proper size. Then, at runtime, the support is checked and will error
   out if a program id is passed when the kernel does not support it.
 - <csr-id-139f3826383daba9a10dc7aacc079f31d28980fc/> add support for map-bound XDP programs
   Such programs are to be bound to cpumap or devmap instead of the usual
   network interfaces.
 - <csr-id-f41592663cda156082255b93db145cfdd19378e5/> `MapFd` and `SockMapFd` are owned
 - <csr-id-c139627f8f180638b786b5e3cd48b8473d96fe56/> reduce indirection in section parsing
   Remove repetition of permitted cgroup attach types. Make optionality of
   name more explicit rather than pretending both kind and name are equal
   to section.
 - <csr-id-89bc255f1d14d72a61064b9b40b641b58f8970e0/> MapData::fd is non-optional
   The primary driver of change here is that `MapData::create` is now a
   factory function that returns `Result<Self, _>` rather than mutating
   `&mut self`. The remaining changes are consequences of that change, the
   most notable of which is the removal of several errors which are no
   longer possible.
 - <csr-id-02124002c88d7a89d6c9afd89857c4c301e09801/> Add clang-format
 - <csr-id-dfb6020a1dc1d0ee28426bd9e3086dd449f643f7/> s/types.types[i]/*t/ where possible
   We already have a mutable reference in scope, use it where possible.
 - <csr-id-098d4364bd0fb8551f0515cb84afda6aff23ed7f/> Mutate BTF in-place without clone
   The BTF we're working on is Cow anyway so modifying in-place is fine.
   All we need to do is store some information before we start our
   mutable iteration to avoid concurrently borrowing types both mutably and
   immutably.
 - <csr-id-826e0e5050e9bf9e0cdff6d2a20c1169820d0e57/> use Self instead of restating the type
 - <csr-id-2a054d76ae167e7c2a6b4bfb1cf51770f93d394a/> avoid multiple vector allocations
   Rather than creating an empty vector and iteratively appending - which
   might induce intermediate allocations - create an ExactSizeIterator and
   collect it into a vector, which should produce exactly one allocation.
 - <csr-id-79ea64ca7fd3cc1b17573b539fd8fa8e76644beb/> Fix (func|line)_info multiple progs in section
   This commit fixes the (func|line)_info when we have multiple programs in
   the same section. The integration test reloc.bpf.c serves as our test
   case here. This required filtering down the (func|line)_info to only
   that in scope of the current symbol + then adjusting the offets to
   appease the kernel.
 - <csr-id-cca9b8f1a7e345a39d852bd18a43974871d3ed4b/> Remove name from ProgramSection
   The name here is never used as we get the program name from the symbol
   table instead.
 - <csr-id-677e7bda4a826aca858311670d1592162b682dff/> Propagate sleepable into ProgramSection
 - <csr-id-bf7fdff1cef28961f096d1c1e00181e0a0c2d14e/> Find programs using the symbol table
   This makes a few changes to the way that Aya reads the ELF object
   files.
   
   1. To find programs in a section, we use the symbols table. This allows
      for cases where multiple programs could appear in the same section.
   2. When parsing our ELF file we build symbols_by_section_index as an
      optimization as we use it for legacy maps, BTF maps and now programs.
   
   As a result of theses changes the "NAME" used in `bpf.prog_mut("NAME")`
   is now ALWAYS the same as the function name in the eBPF code, making the
   user experience more consistent.
 - <csr-id-17f25a67934ad10443a4fbb62a563b5f6edcaa5f/> better panic messages
   Always include operands in failing assertions. Use assert_matches over
   manual match + panic.
 - <csr-id-96fa08bd82233268154edf30b106876f5a4f0e30/> Define dependencies on the workspace level
   This way we will avoid version mismatches and make differences in
   features across our crates clearer.
 - <csr-id-6f2a8c8a5c47098fb5e5a75ecebdff493d486c97/> avoid an allocation
 - <csr-id-d71d1e199382379036dc4760e4edbd5e637e07c3/> remove dead code
   This logic moved in bb595c4e69ff0c72c8327e7f64d43ca7a4bc16a3. The
   mutation here prevented the compiler from noticing.
 - <csr-id-27120b328aac5f992eed98b03216a9880a381749/> don't allocate static strings
 - <csr-id-d9dfd94f29be8c28b7fe0ef4ab560db49f7514fb/> aya-obj: Make it possible to externally assemble BtfEnum
 - <csr-id-47f764c19185a69a00f3925239797caa98cd5afe/> Make Features part of the public API
   This commit adds a new probe for bpf_attach_cookie, which would be used
   to implement USDT probes. Since USDT probes aren't currently supported,
   we this triggers a dead_code warning in clippy.
   
   There are cases where exposing FEATURES - our lazy static - is actually
   helpful to users of the library. For example, they may wish to choose to
   load a different version of their bytecode based on current features.
   Or, in the case of an orchestrator like bpfd, we might want to allow
   users to describe which features their program needs and return nice
   error message is one or more nodes in their cluster doesn't support the
   necessary feature set.
   
   To do this without breaking the API, we make all the internal members of
   the `Features` and `BtfFeatures` structs private, and add accessors for
   them. We then add a `features()` API to avoid leaking the
   lazy_static.
 - <csr-id-93435fc85400aa036f3890c43c78c9c9eb4baa96/> allow global value to be optional
   This allow to not error out when a global symbol is missing from the object.
 - <csr-id-f5f8083441afd2daed9344fc2031878d574efaf1/> update hashbrown requirement from 0.13 to 0.14
   Updates the requirements on [hashbrown](https://github.com/rust-lang/hashbrown) to permit the latest version.
   - [Changelog](https://github.com/rust-lang/hashbrown/blob/master/CHANGELOG.md)
   - [Commits](https://github.com/rust-lang/hashbrown/compare/v0.13.1...v0.14.0)
   
   ---
   updated-dependencies:
   - dependency-name: hashbrown
     dependency-type: direct:production
   ...
 - <csr-id-fa3dd4bef252566aa26577a0d42b2ff59ac2ff2a/> update rbpf requirement from 0.1.0 to 0.2.0
   Updates the requirements on [rbpf](https://github.com/qmonnet/rbpf) to permit the latest version.
   - [Commits](https://github.com/qmonnet/rbpf/compare/v0.1.0...v0.2.0)
   
   ---
   updated-dependencies:
   - dependency-name: rbpf
     dependency-type: direct:production
   ...
 - <csr-id-35eaa50736d9e894eb5122b1070afd7b0442eae6/> Make relocations less strict
   Missing relocations at load time shouldn't cause an error in aya-obj
   but instead poison related instructions.
   
   This makes struct flavors work.
 - <csr-id-c4e721f3d334a7c2e5e6d6cd6f4ade0f1334be72/> Apply BTF relocations to all functions
   This fix aya wrong logic causing non entrypoint functions to not have
   any BTF relocations working.
   
   Also fix missing section_offset computation for instruction offset in
   multiple spots.
 - <csr-id-591e21267a9bc9adca9818095de5a695cee7ee9b/> Do not create data maps on kernel without global data support
   Fix map creation failure when a BPF have a data section on older
   kernel. (< 5.2)
   
   If the BPF uses that section, relocation will fail accordingly and
   report an error.
 - <csr-id-18b3d75d096e3c90f8c5b2f7292637a3369f96a6/> Fix ProgramSection::from_str for bss and rodata sections
 - <csr-id-9e1109b3ce70a3668771bd11a7fda101eec3ab93/> Move program's functions to the same map
 - <csr-id-4c78f7f1a014cf54d54c805233a0f29eb1ca5eeb/> update object requirement from 0.30 to 0.31
   Updates the requirements on [object](https://github.com/gimli-rs/object) to permit the latest version.
   - [Release notes](https://github.com/gimli-rs/object/releases)
   - [Changelog](https://github.com/gimli-rs/object/blob/master/CHANGELOG.md)
   - [Commits](https://github.com/gimli-rs/object/compare/0.30.0...0.31.0)
   
   ---
   updated-dependencies:
   - dependency-name: object
     dependency-type: direct:production
   ...
 - <csr-id-33a0a2b604e77b63b771b9d0e167c894793492b5/> flip feature "no_std" to feature "std"
   This fixes `cargo build --all-features` by sidestepping the feature
   unification problem described in The Cargo Book[0].
   
   Add `cargo hack --feature-powerset` to CI to enforce that this doesn't
   regress (and that all combinations of features work).
   
   Since error_in_core is nightly-only, use core-error and a fake std
   module to allow aya-obj to build without std on stable.
   
   [0] https://doc.rust-lang.org/cargo/reference/features.html#feature-unification
 - <csr-id-1132b6e01b86856aa1fddf179fcc7e3825e79406/> Add sanitize code for kernels without bpf_probe_read_kernel
   Required for kernel before 5.5.
   
   Also move Features to aya-obj.
 - <csr-id-4e33fa011e87cdc2fc59025b9e531b4872651cd0/> fix DATASEC to STRUCT conversion
   This fix the following issues:
   - Previously the DATASEC name wasn't sanitized resulting on "Invalid
     name" returned by old kernels.
   - The newly created BTF struct had a size of 0 making old kernels refuse
     it.
   
   This was tested on Debian 10 with kernel 4.19.0-21.
 - <csr-id-93ac3e94bcb47864670c124dfe00e16ed2ab6f5e/> support relocations across multiple text sections + fixes
   Fix R_BPF_64_64 text relocations in sections other than .text (for
   instance .text.unlikely). Also fix misc bugs triggered by integration
   tests.
 - <csr-id-b25a08981986cac4f511433d165560576a8c9856/> change two drain() calls to into_iter()
 - <csr-id-5c4f1d69a60e0c5324512a7cfbc4467b7f5d0bca/> rework `maps` section parsing
   Avoid allocations and add comments explaining how things work.
 - <csr-id-dfbe1207c1bbd105d1daa9b08cec0e9803b5464e/> fix compilation with nightly
 - <csr-id-7479c1dd6c1356bddb0401dbeea65618674524c9/> More discrete feature logging
   Just use the Debug formatter vs. printing a message for each probe.
 - <csr-id-ce22ca668f3e7c0f9832d28370457204537d2e50/> Make features a lazy_static
 - <csr-id-376c48640033fdbf8b5199641f353587273f8a32/> Add multibuffer support for XDP
 - <csr-id-a18693b42dc986bde06b07540e261ecac59eef24/> Add support for multibuffer programs
   This adds support for loading XDP programs that are multi-buffer
   capable, which is signalled using the xdp.frags section name. When this
   is set, we should set the BPF_F_XDP_HAS_FRAGS flag when loading the
   program into the kernel.
 - <csr-id-9a6f8143a1a4c5c88a373701d74d96596c75242f/> btf: add support for BTF_KIND_ENUM64
 - <csr-id-4482db42d86c657826efe80f484f57a601ed2f38/> btf: fix relocations for signed enums (32 bits)
   Enums now carry a signed bit in the info flags. Take it into account
   when applying enum relocations.
 - <csr-id-d6b976c6f1f6163680c179502f4f454d0cec747e/> btf: switch ComputedRelocationValue::value to u64
   This is in preparation of adding Enum64 relocation support
 - <csr-id-3d03c8a8e0a9033be8c1ab020129db7790cc7493/> Add new map types
   Include all new map types which were included in the last libbpf update
   (5d13fd5acaa9).
 - <csr-id-cb28533e2f9eb0b2cd80f4bf9515cdec31763749/> Update `BPF_MAP_TYPE_CGROUP_STORAGE` name to `BPF_MAP_TYPE_CGRP_STORAGE`
   It changed in libbpf
 - <csr-id-9c451a3357317405dd8e2e4df7d006cee943adcc/> update documentation and versioning info
   - Set the version number of `aya-obj` to `0.1.0`.
   - Update the description of the `aya-obj` crate.
   - Add a section in README and rustdoc warning about the unstable API.
 - <csr-id-772af170aea2feccb5e98cc84125e9e31b9fbe9a/> add documentation on program names
   This commit adds documentation on how program names are parsed from
   section names, as is used by `aya_obj::Object.programs` as HashMap keys,
   and updates the examples into using program names.
 - <csr-id-9ec3447e891ca770a65f8ff9b71884f25530f515/> fix rustfmt diffs and typos
 - <csr-id-30f1fabc05654e8d11dd2648767895123c141c3b/> add no_std feature
   The crate has few libstd dependencies. Since it should be platform-
   independent in principle, making it no_std like the object crate would
   seem reasonable.
   
   However, the feature `error_in_core` is not yet stabilized, and the
   thiserror crate currently offers no no_std support. When the feature
   no_std is selected, we enable the `error_in_core` feature, switch to
   thiserror-core and replace the HashMap with the one in hashbrown.
 - <csr-id-311ead6760ce53e9503af00391e6631f7387ab4a/> add integration tests against rbpf
 - <csr-id-e52497cb9c02123ae450ca36fb6f898d24b25c4b/> add basic documentation to public members
   Types relevant to maps are moved into aya_obj::maps.
   Some members are marked `pub(crate)` again.
 - <csr-id-ac49827e204801079be2b87160a795ef412bd6cb/> migrate aya::obj into a separate crate
   To split the crate into two, several changes were made:
   1. Most `pub(crate)` are now `pub` to allow access from Aya;
   2. Parts of BpfError are merged into, for example, RelocationError;
   3. BTF part of Features is moved into the new crate;
   4. `#![deny(missing_docs)]` is removed temporarily;
   5. Some other code gets moved into the new crate, mainly:
      - aya::{bpf_map_def, BtfMapDef, PinningType},
      - aya::programs::{CgroupSock*AttachType},
   
   The new crate is currenly allowing missing_docs. Member visibility
   will be adjusted later to minimize exposure of implementation details.
 - <csr-id-81bc307dce452f0aacbfbe8c304089d11ddd8c5e/> migrate bindgen destination

### Test

 - <csr-id-572d047e37111b732be49ef3ad6fb16f70aa4063/> avoid lossy string conversions
   We can be strict in tests.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 146 commits contributed to the release.
 - 63 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 1 unique issue was worked on: [#608](https://github.com/aya-rs/aya/issues/608)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#608](https://github.com/aya-rs/aya/issues/608)**
    - Fix load errors for empty (but existent) BTF/BTF.ext sections ([`5894c4c`](https://github.com/aya-rs/aya/commit/5894c4ce82948c7e5fe766f41b690d036fcca907))
 * **Uncategorized**
    - Release aya-obj v0.1.0, aya v0.12.0, safety bump aya-log v0.2.0 ([`0e99fa0`](https://github.com/aya-rs/aya/commit/0e99fa0f340b2fb2e0da3b330aa6555322a77eec))
    - Merge pull request #891 from dave-tucker/changelog ([`431ce23`](https://github.com/aya-rs/aya/commit/431ce23f27ef5c36a6b38c73b38f23b1cf007900))
    - Add CHANGELOG ([`72e8aab`](https://github.com/aya-rs/aya/commit/72e8aab6c8be8663c5b6ff6b606a51debf512f7d))
    - Appease new nightly clippy lints ([`3369169`](https://github.com/aya-rs/aya/commit/3369169aaca6510a47318fc29bbdb801b60b1c21))
    - Merge pull request #882 from dave-tucker/metadata ([`0fadd69`](https://github.com/aya-rs/aya/commit/0fadd695377b8a3f0d9a3af3bc8140f0f1bed8d2))
    - Use the cargo workspace package table ([`b3e7ef7`](https://github.com/aya-rs/aya/commit/b3e7ef741c5b8d09fc7dc8302576f8174be75ff4))
    - Merge pull request #885 from dave-tucker/nightly-up ([`2d72197`](https://github.com/aya-rs/aya/commit/2d721971cfae39e168f0dc4dac1f219490c16fbf))
    - Appease clippy unused imports ([`770a95e`](https://github.com/aya-rs/aya/commit/770a95e0779a6a943c2f5439334fa208ac2ca7e6))
    - Handle lack of match of enum variants correctly ([`c05a3b6`](https://github.com/aya-rs/aya/commit/c05a3b69b7a94036c380bd64c6de51377987077c))
    - Don't parse labels as programs ([`35e21ae`](https://github.com/aya-rs/aya/commit/35e21ae0079d38e90d90fc85d29580c8b44b16d4))
    - Merge pull request #812 from tamird/redundant-cargo ([`715d490`](https://github.com/aya-rs/aya/commit/715d49022eefb152ef8817c730d9eac2b3e6d66f))
    - Remove redundant keys ([`cc48523`](https://github.com/aya-rs/aya/commit/cc48523347c2be5520779ef8eeadc6d3a68649d0))
    - Merge pull request #797 from aya-rs/rustfmt-group-imports ([`373fb7b`](https://github.com/aya-rs/aya/commit/373fb7bf06ba80ee4c120d8c112f5e810204c472))
    - Group_imports = "StdExternalCrate" ([`d16e607`](https://github.com/aya-rs/aya/commit/d16e607fd4b6258b516913071fdacafeb2bbbff9))
    - Merge pull request #527 from Tuetuopay/xdpmaps ([`7f9ce06`](https://github.com/aya-rs/aya/commit/7f9ce062f4b8b5cefbe07d8ea47363266f7eacd1))
    - Aya, bpf: misc fixes following review comments ([`579e3ce`](https://github.com/aya-rs/aya/commit/579e3cee22ae8e932efb0894ca7fd9ceb91ca7fa))
    - Make maps work on kernels not supporting ProgIds ([`00dc7a5`](https://github.com/aya-rs/aya/commit/00dc7a5bd4468b7d86d7f167a49e78d89016e2ac))
    - Add support for map-bound XDP programs ([`139f382`](https://github.com/aya-rs/aya/commit/139f3826383daba9a10dc7aacc079f31d28980fc))
    - Merge pull request #770 from aya-rs/mapfd-is-owned ([`41d01f6`](https://github.com/aya-rs/aya/commit/41d01f638bc81306749dd0f6aa7d2a677f4de27b))
    - `MapFd` and `SockMapFd` are owned ([`f415926`](https://github.com/aya-rs/aya/commit/f41592663cda156082255b93db145cfdd19378e5))
    - Merge pull request #766 from aya-rs/obj-better-sense ([`e9690df`](https://github.com/aya-rs/aya/commit/e9690df834b502575321ba32fd09f93eaacb03fa))
    - Reduce indirection in section parsing ([`c139627`](https://github.com/aya-rs/aya/commit/c139627f8f180638b786b5e3cd48b8473d96fe56))
    - Merge pull request #742 from aya-rs/avoid-utf-assumption ([`8ffd9bb`](https://github.com/aya-rs/aya/commit/8ffd9bb236a4dfc7694bbdac2b6ea1236b238582))
    - Avoid lossy string conversions ([`572d047`](https://github.com/aya-rs/aya/commit/572d047e37111b732be49ef3ad6fb16f70aa4063))
    - Merge pull request #758 from aya-rs/map-fd-not-option ([`1d5f764`](https://github.com/aya-rs/aya/commit/1d5f764d07c06fa25167d1d4cf341913d4f0cd01))
    - MapData::fd is non-optional ([`89bc255`](https://github.com/aya-rs/aya/commit/89bc255f1d14d72a61064b9b40b641b58f8970e0))
    - Merge pull request #749 from dave-tucker/clang-format ([`8ce1c00`](https://github.com/aya-rs/aya/commit/8ce1c00ad8b4ac1362eaf24d99eafd848546c9d3))
    - Add clang-format ([`0212400`](https://github.com/aya-rs/aya/commit/02124002c88d7a89d6c9afd89857c4c301e09801))
    - Merge pull request #734 from aya-rs/reduce-slicing ([`d3513e7`](https://github.com/aya-rs/aya/commit/d3513e7010cdab04a3d8bb5c7e7518ff67548302))
    - S/types.types[i]/*t/ where possible ([`dfb6020`](https://github.com/aya-rs/aya/commit/dfb6020a1dc1d0ee28426bd9e3086dd449f643f7))
    - Merge pull request #725 from dave-tucker/enum64 ([`2a55fc7`](https://github.com/aya-rs/aya/commit/2a55fc7bd3a15340b5b644d668f3a387bbdb09d3))
    - Aya, aya-obj: Implement ENUM64 fixups ([`e38e256`](https://github.com/aya-rs/aya/commit/e38e2566e3393034b37c299e50c6a4b70d51ad1d))
    - Merge pull request #731 from dave-tucker/noclone-btf ([`e210012`](https://github.com/aya-rs/aya/commit/e21001226fc05840867f43f6a4455a4c919e3b91))
    - Mutate BTF in-place without clone ([`098d436`](https://github.com/aya-rs/aya/commit/098d4364bd0fb8551f0515cb84afda6aff23ed7f))
    - Merge pull request #726 from aya-rs/btf-iter-alloc ([`761e4dd`](https://github.com/aya-rs/aya/commit/761e4ddbe3abf8b9177ebd6984465fe66696728a))
    - Use Self instead of restating the type ([`826e0e5`](https://github.com/aya-rs/aya/commit/826e0e5050e9bf9e0cdff6d2a20c1169820d0e57))
    - Avoid multiple vector allocations ([`2a054d7`](https://github.com/aya-rs/aya/commit/2a054d76ae167e7c2a6b4bfb1cf51770f93d394a))
    - Merge pull request #721 from dave-tucker/fix-funcinfo ([`1979da9`](https://github.com/aya-rs/aya/commit/1979da92a722bacd9c984865a4c7108e22fb618f))
    - Fix (func|line)_info multiple progs in section ([`79ea64c`](https://github.com/aya-rs/aya/commit/79ea64ca7fd3cc1b17573b539fd8fa8e76644beb))
    - Merge pull request #720 from dave-tucker/programsection-noname ([`e915379`](https://github.com/aya-rs/aya/commit/e9153792f1c18caa5899edc7c05487eb291415a4))
    - Remove name from ProgramSection ([`cca9b8f`](https://github.com/aya-rs/aya/commit/cca9b8f1a7e345a39d852bd18a43974871d3ed4b))
    - Merge pull request #711 from dave-tucker/sleepable ([`77e9603`](https://github.com/aya-rs/aya/commit/77e9603976b58491427df049a163e1945bc0bf27))
    - Propagate sleepable into ProgramSection ([`677e7bd`](https://github.com/aya-rs/aya/commit/677e7bda4a826aca858311670d1592162b682dff))
    - Merge pull request #413 from dave-tucker/fix-names-once-and-for-all ([`e833a71`](https://github.com/aya-rs/aya/commit/e833a71b022b39fa7c7a904b74ef0c55ff7c19ee))
    - Merge pull request #704 from aya-rs/better-panic ([`868a9b0`](https://github.com/aya-rs/aya/commit/868a9b00b3701a4e035dc1d70cac934ef836655b))
    - Find programs using the symbol table ([`bf7fdff`](https://github.com/aya-rs/aya/commit/bf7fdff1cef28961f096d1c1e00181e0a0c2d14e))
    - Better panic messages ([`17f25a6`](https://github.com/aya-rs/aya/commit/17f25a67934ad10443a4fbb62a563b5f6edcaa5f))
    - Merge pull request #699 from aya-rs/cache-again-god-damn-it ([`e95f76a`](https://github.com/aya-rs/aya/commit/e95f76a5b348070dd6833d37ea16db04f6afa612))
    - Do not escape newlines on Err(LoadError).unwrap() ([`8961be9`](https://github.com/aya-rs/aya/commit/8961be95268d2a4464ef75b0898cf07f9ba44470))
    - Merge pull request #667 from vadorovsky/workspace-dependencies ([`f554d42`](https://github.com/aya-rs/aya/commit/f554d421053bc34266afbf8e00b28705ab4b41d2))
    - Define dependencies on the workspace level ([`96fa08b`](https://github.com/aya-rs/aya/commit/96fa08bd82233268154edf30b106876f5a4f0e30))
    - Merge pull request #665 from aya-rs/dead-code-rm ([`893ab76`](https://github.com/aya-rs/aya/commit/893ab76afaa9f729967eec47cc211f0a46f6268e))
    - Avoid an allocation ([`6f2a8c8`](https://github.com/aya-rs/aya/commit/6f2a8c8a5c47098fb5e5a75ecebdff493d486c97))
    - Remove dead code ([`d71d1e1`](https://github.com/aya-rs/aya/commit/d71d1e199382379036dc4760e4edbd5e637e07c3))
    - Merge pull request #656 from aya-rs/kernel-version-fml ([`232cd45`](https://github.com/aya-rs/aya/commit/232cd45e41031060238d37fc7f08eb3d63fa2eeb))
    - Replace matches with assert_matches ([`961f45d`](https://github.com/aya-rs/aya/commit/961f45da37616b912d2d4ed594036369f3f8285b))
    - Merge pull request #650 from aya-rs/test-cleanup ([`61608e6`](https://github.com/aya-rs/aya/commit/61608e64583f9dc599eef9b8db098f38a765b285))
    - Run tests with powerset of features ([`8e9712a`](https://github.com/aya-rs/aya/commit/8e9712ac024cbc05dfe8ba09a9dd725e56e34a51))
    - Merge pull request #648 from aya-rs/clippy-more ([`a840a17`](https://github.com/aya-rs/aya/commit/a840a17308c1c27867e67baa62942738c5bd2caf))
    - Clippy over tests and integration-ebpf ([`e621a09`](https://github.com/aya-rs/aya/commit/e621a09181d0a5ddb6289d8b13d4b89a71de63f1))
    - Merge pull request #643 from aya-rs/procfs ([`6e9aba5`](https://github.com/aya-rs/aya/commit/6e9aba55fe8d23aa337b29a1cab890bb54816068))
    - Remove verifier log special case ([`b5ebcb7`](https://github.com/aya-rs/aya/commit/b5ebcb7cc5fd0f719567b97f682a0ea0f8e0dc13))
    - Merge pull request #641 from aya-rs/logger-messages-plz ([`4c0983b`](https://github.com/aya-rs/aya/commit/4c0983bca962e0e9b2711805ae7fbc6b53457c34))
    - Hide details of VerifierLog ([`6b94b20`](https://github.com/aya-rs/aya/commit/6b94b2080dc4c122954beea814b2a1a4569e9aa3))
    - Use procfs crate for kernel version parsing ([`b611038`](https://github.com/aya-rs/aya/commit/b611038d5b41a45ca70553550dbdef9aa1fd117c))
    - Merge pull request #642 from aya-rs/less-strings ([`32be47a`](https://github.com/aya-rs/aya/commit/32be47a23b94902caadcc7bb1612adbd18318eca))
    - Don't allocate static strings ([`27120b3`](https://github.com/aya-rs/aya/commit/27120b328aac5f992eed98b03216a9880a381749))
    - Merge pull request #635 from marysaka/misc/aya-obj-enum-public ([`5c86b7e`](https://github.com/aya-rs/aya/commit/5c86b7ee950762d1cc37fc39c788e670869db231))
    - Aya-obj: Make it possible to externally assemble BtfEnum ([`d9dfd94`](https://github.com/aya-rs/aya/commit/d9dfd94f29be8c28b7fe0ef4ab560db49f7514fb))
    - Merge pull request #531 from dave-tucker/probe-cookie ([`bc0d021`](https://github.com/aya-rs/aya/commit/bc0d02143f5bc6103cca27d5f0c7a40beacd0668))
    - Make Features part of the public API ([`47f764c`](https://github.com/aya-rs/aya/commit/47f764c19185a69a00f3925239797caa98cd5afe))
    - Merge pull request #632 from marysaka/feat/global-data-optional ([`b2737d5`](https://github.com/aya-rs/aya/commit/b2737d5b0d18ce09202ca9eb2ce772b1144ea6b8))
    - Allow global value to be optional ([`93435fc`](https://github.com/aya-rs/aya/commit/93435fc85400aa036f3890c43c78c9c9eb4baa96))
    - Merge pull request #626 from aya-rs/dependabot/cargo/hashbrown-0.14 ([`26c6b92`](https://github.com/aya-rs/aya/commit/26c6b92ef1d58d0703a4a020db02dca65911456c))
    - Update hashbrown requirement from 0.13 to 0.14 ([`f5f8083`](https://github.com/aya-rs/aya/commit/f5f8083441afd2daed9344fc2031878d574efaf1))
    - Merge pull request #623 from aya-rs/dependabot/cargo/rbpf-0.2.0 ([`53ec1f2`](https://github.com/aya-rs/aya/commit/53ec1f23ea4efe7c686a6a4fb8bb166c8d444dc8))
    - Update rbpf requirement from 0.1.0 to 0.2.0 ([`fa3dd4b`](https://github.com/aya-rs/aya/commit/fa3dd4bef252566aa26577a0d42b2ff59ac2ff2a))
    - Merge pull request #563 from marysaka/fix/reloc-less-strict ([`85ad019`](https://github.com/aya-rs/aya/commit/85ad0197e0e0e30c99f3af63584f9c569b752a50))
    - Make relocations less strict ([`35eaa50`](https://github.com/aya-rs/aya/commit/35eaa50736d9e894eb5122b1070afd7b0442eae6))
    - Merge pull request #602 from marysaka/fix/btf-reloc-all-functions ([`3a9a54f`](https://github.com/aya-rs/aya/commit/3a9a54fd9b2f69e2427accbe0451761ecc537197))
    - Merge pull request #616 from nak3/fix-bump ([`3211d2c`](https://github.com/aya-rs/aya/commit/3211d2c92801d8208c76856cb271f2b7772a0313))
    - Apply BTF relocations to all functions ([`c4e721f`](https://github.com/aya-rs/aya/commit/c4e721f3d334a7c2e5e6d6cd6f4ade0f1334be72))
    - [codegen] Update libbpf to f7eb43b90f4c8882edf6354f8585094f8f3aade0Update libbpf to f7eb43b90f4c8882edf6354f8585094f8f3aade0 ([`0bc886f`](https://github.com/aya-rs/aya/commit/0bc886f1634443d202e24f56cb74d3dce2e66e37))
    - Merge pull request #585 from probulate/tag-len-value ([`5165bf2`](https://github.com/aya-rs/aya/commit/5165bf2f99cdc228122bdab505c2059723e95a9f))
    - Merge pull request #605 from marysaka/fix/global-data-reloc-ancient-kernels ([`9c437aa`](https://github.com/aya-rs/aya/commit/9c437aafd96bebc5c90fdc7f370b5415174b1019))
    - Merge pull request #604 from marysaka/fix/section-kind-from-str ([`3a9058e`](https://github.com/aya-rs/aya/commit/3a9058e7625b56ac26d6bb592dd4c3a93c61d6b0))
    - Do not create data maps on kernel without global data support ([`591e212`](https://github.com/aya-rs/aya/commit/591e21267a9bc9adca9818095de5a695cee7ee9b))
    - Fix ProgramSection::from_str for bss and rodata sections ([`18b3d75`](https://github.com/aya-rs/aya/commit/18b3d75d096e3c90f8c5b2f7292637a3369f96a6))
    - Build tests with all features ([`4e2f832`](https://github.com/aya-rs/aya/commit/4e2f8322cc6ee7ef06a1d5718405964e8da14d18))
    - Move program's functions to the same map ([`9e1109b`](https://github.com/aya-rs/aya/commit/9e1109b3ce70a3668771bd11a7fda101eec3ab93))
    - Merge pull request #597 from nak3/test-clippy ([`7cd1c64`](https://github.com/aya-rs/aya/commit/7cd1c642e35d271c75eb1e9d65988e539a90f2bf))
    - Drop unnecessary mut ([`e67025b`](https://github.com/aya-rs/aya/commit/e67025b66f08592bb7e9a3273d56eb5669b16d90))
    - Merge pull request #577 from aya-rs/dependabot/cargo/object-0.31 ([`deb054a`](https://github.com/aya-rs/aya/commit/deb054afa45cfb9ffb7b213f34fc549c9503c0dd))
    - Merge pull request #545 from epompeii/lsm_sleepable ([`120b59d`](https://github.com/aya-rs/aya/commit/120b59dd2e42805cf5880ada8f1bd0ba5faf4a44))
    - Update object requirement from 0.30 to 0.31 ([`4c78f7f`](https://github.com/aya-rs/aya/commit/4c78f7f1a014cf54d54c805233a0f29eb1ca5eeb))
    - Merge pull request #586 from probulate/no-std-inversion ([`45efa63`](https://github.com/aya-rs/aya/commit/45efa6384ffbcff82ca55e151c446d930147abf0))
    - Flip feature "no_std" to feature "std" ([`33a0a2b`](https://github.com/aya-rs/aya/commit/33a0a2b604e77b63b771b9d0e167c894793492b5))
    - Merge branch 'aya-rs:main' into lsm_sleepable ([`1f2006b`](https://github.com/aya-rs/aya/commit/1f2006bfde865cc4308643b21d51cf4a8e69d6d4))
    - Merge pull request #583 from 0xrawsec/fix-builtin-linkage ([`b2d5059`](https://github.com/aya-rs/aya/commit/b2d5059ac250b4017ba723e594292f0356c31811))
    - - comment changed to be more precise - adapted test to be more readable ([`1464bdc`](https://github.com/aya-rs/aya/commit/1464bdc1d4393e1a4ab5cff3833f784444b1d175))
    - Added memmove, memcmp to the list of function changed to BTF_FUNC_STATIC ([`72c1572`](https://github.com/aya-rs/aya/commit/72c15721781f758c65cd4b94def8e907e42d8c35))
    - Fixed indent ([`a51c9bc`](https://github.com/aya-rs/aya/commit/a51c9bc532f101302a38cd866b40a5014fa61c54))
    - Removed useless line break and comments ([`5b4fc9e`](https://github.com/aya-rs/aya/commit/5b4fc9ea93f32da4c58be4b261905b883c9ea20b))
    - Add debug messages ([`74bc754`](https://github.com/aya-rs/aya/commit/74bc754862df5571a4fafb18260bc1e5c4acd9b2))
    - Merge pull request #582 from marysaka/feature/no-kern-read-sanitizer ([`b5c2928`](https://github.com/aya-rs/aya/commit/b5c2928b0e0d20c48157a5862f0d2c3dd5dbb784))
    - Add sanitize code for kernels without bpf_probe_read_kernel ([`1132b6e`](https://github.com/aya-rs/aya/commit/1132b6e01b86856aa1fddf179fcc7e3825e79406))
    - Fixed BTF linkage of memset and memcpy to static ([`4e41da6`](https://github.com/aya-rs/aya/commit/4e41da6a86418e4e2a9241b42301a1abe38e7372))
    - Merge pull request #581 from marysaka/fix/datasec-struct-conversion ([`858f77b`](https://github.com/aya-rs/aya/commit/858f77bf2cfb457765b7deb81ba75fb706c71954))
    - Fix DATASEC to STRUCT conversion ([`4e33fa0`](https://github.com/aya-rs/aya/commit/4e33fa011e87cdc2fc59025b9e531b4872651cd0))
    - Merge pull request #572 from alessandrod/reloc-fixes ([`542ada3`](https://github.com/aya-rs/aya/commit/542ada3fe7f9d4d06542253361acc5fadce3f24b))
    - Support relocations across multiple text sections + fixes ([`93ac3e9`](https://github.com/aya-rs/aya/commit/93ac3e94bcb47864670c124dfe00e16ed2ab6f5e))
    - Change two drain() calls to into_iter() ([`b25a089`](https://github.com/aya-rs/aya/commit/b25a08981986cac4f511433d165560576a8c9856))
    - Aya, aya-obj: refactor map relocations ([`401ea5e`](https://github.com/aya-rs/aya/commit/401ea5e8482ece34b6c88de85ec474bdfc577fd4))
    - Rework `maps` section parsing ([`5c4f1d6`](https://github.com/aya-rs/aya/commit/5c4f1d69a60e0c5324512a7cfbc4467b7f5d0bca))
    - Review ([`85714d5`](https://github.com/aya-rs/aya/commit/85714d5cf3622da49d1442c34caa63451d9efe48))
    - Macro ([`6dfb9d8`](https://github.com/aya-rs/aya/commit/6dfb9d82af9c178f4effd7a0c9095442816a014c))
    - Obj ([`6a25d4d`](https://github.com/aya-rs/aya/commit/6a25d4ddec42e3408bd823fccc6e64c33575bc5c))
    - Fix compilation with nightly ([`dfbe120`](https://github.com/aya-rs/aya/commit/dfbe1207c1bbd105d1daa9b08cec0e9803b5464e))
    - Merge pull request #537 from aya-rs/codegen ([`8684a57`](https://github.com/aya-rs/aya/commit/8684a5783db6953b28e42bbbcdc52514fc4e6c37))
    - [codegen] Update libbpf to a41e6ef3251cba858021b90c33abb9efdb17f575Update libbpf to a41e6ef3251cba858021b90c33abb9efdb17f575 ([`24f15ea`](https://github.com/aya-rs/aya/commit/24f15ea25f413633f8c498ee5be046e797acebae))
    - More discrete feature logging ([`7479c1d`](https://github.com/aya-rs/aya/commit/7479c1dd6c1356bddb0401dbeea65618674524c9))
    - Make features a lazy_static ([`ce22ca6`](https://github.com/aya-rs/aya/commit/ce22ca668f3e7c0f9832d28370457204537d2e50))
    - Merge pull request #519 from dave-tucker/frags ([`bc83f20`](https://github.com/aya-rs/aya/commit/bc83f208b11542607e02751126a68b1ca568873b))
    - Add multibuffer support for XDP ([`376c486`](https://github.com/aya-rs/aya/commit/376c48640033fdbf8b5199641f353587273f8a32))
    - Add support for multibuffer programs ([`a18693b`](https://github.com/aya-rs/aya/commit/a18693b42dc986bde06b07540e261ecac59eef24))
    - Merge pull request #453 from alessandrod/btf-kind-enum64 ([`e8e2767`](https://github.com/aya-rs/aya/commit/e8e276730e7351888a71f1196ca1bfbc06c22432))
    - Btf: add support for BTF_KIND_ENUM64 ([`9a6f814`](https://github.com/aya-rs/aya/commit/9a6f8143a1a4c5c88a373701d74d96596c75242f))
    - Merge pull request #501 from alessandrod/fix-enum32-relocs ([`f81b1b9`](https://github.com/aya-rs/aya/commit/f81b1b9f3ec1de5241d8882da56f1d8d7c22d994))
    - Btf: fix relocations for signed enums (32 bits) ([`4482db4`](https://github.com/aya-rs/aya/commit/4482db42d86c657826efe80f484f57a601ed2f38))
    - Btf: switch ComputedRelocationValue::value to u64 ([`d6b976c`](https://github.com/aya-rs/aya/commit/d6b976c6f1f6163680c179502f4f454d0cec747e))
    - Fix lints ([`9f4ef6f`](https://github.com/aya-rs/aya/commit/9f4ef6f67df397c7e243435ccb3bdd517fd467cf))
    - Merge pull request #487 from vadorovsky/new-map-types ([`42c4a8b`](https://github.com/aya-rs/aya/commit/42c4a8be7c502d7e7508c636f7c1cb28296c26b8))
    - Add new map types ([`3d03c8a`](https://github.com/aya-rs/aya/commit/3d03c8a8e0a9033be8c1ab020129db7790cc7493))
    - Merge pull request #483 from aya-rs/codegen ([`0399991`](https://github.com/aya-rs/aya/commit/03999913833ad576d9ba7d1c0123703f49b340a5))
    - Update `BPF_MAP_TYPE_CGROUP_STORAGE` name to `BPF_MAP_TYPE_CGRP_STORAGE` ([`cb28533`](https://github.com/aya-rs/aya/commit/cb28533e2f9eb0b2cd80f4bf9515cdec31763749))
    - [codegen] Update libbpf to 3423d5e7cdab356d115aef7f987b4a1098ede448Update libbpf to 3423d5e7cdab356d115aef7f987b4a1098ede448 ([`5d13fd5`](https://github.com/aya-rs/aya/commit/5d13fd5acaa90efedb76d371b69431ac9a262fdd))
    - Merge pull request #475 from yesh0/aya-obj ([`897957a`](https://github.com/aya-rs/aya/commit/897957ac84370cd1ee463bdf2ff4859333b41012))
    - Update documentation and versioning info ([`9c451a3`](https://github.com/aya-rs/aya/commit/9c451a3357317405dd8e2e4df7d006cee943adcc))
    - Add documentation on program names ([`772af17`](https://github.com/aya-rs/aya/commit/772af170aea2feccb5e98cc84125e9e31b9fbe9a))
    - Fix rustfmt diffs and typos ([`9ec3447`](https://github.com/aya-rs/aya/commit/9ec3447e891ca770a65f8ff9b71884f25530f515))
    - Add no_std feature ([`30f1fab`](https://github.com/aya-rs/aya/commit/30f1fabc05654e8d11dd2648767895123c141c3b))
    - Add integration tests against rbpf ([`311ead6`](https://github.com/aya-rs/aya/commit/311ead6760ce53e9503af00391e6631f7387ab4a))
    - Add basic documentation to public members ([`e52497c`](https://github.com/aya-rs/aya/commit/e52497cb9c02123ae450ca36fb6f898d24b25c4b))
    - Migrate aya::obj into a separate crate ([`ac49827`](https://github.com/aya-rs/aya/commit/ac49827e204801079be2b87160a795ef412bd6cb))
    - Migrate bindgen destination ([`81bc307`](https://github.com/aya-rs/aya/commit/81bc307dce452f0aacbfbe8c304089d11ddd8c5e))
</details>

