# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes

- The implementation is now backed by a ring buffer rather than a perf event. This should improve
  performance but increases the minimum supported kernel version to 5.8.

- Drop the built-in `tokio` dependency. Users must now BYOR (bring your own runtime).

## v0.2.1 (2024-10-09)

### Chore

 - <csr-id-41c61560eae01a30c703ea22c5bfeeff0ecf6b1b/> Rename bpf -> ebpf

### Documentation

 - <csr-id-8830c0bc20c6e3dbbddf63533d4623fcd45dd9af/> reword rustdocs a bit

### New Features

 - <csr-id-8c79b71bd5699a686f33360520aa95c1a2895fa5/> Rename Bpf to Ebpf
   And BpfLoader to EbpfLoader.
   This also adds type aliases to preserve the use of the old names, making
   updating to a new Aya release less of a burden. These aliases are marked
   as deprecated since we'll likely remove them in a later release.
 - <csr-id-a93e3546204115631c11bc0601905c205bf8a584/> Rename BpfLogger to EbpfLogger

### Bug Fixes

 - <csr-id-55ed9e054665ba303e1fb381c7ac590056da7724/> print &[u8] using full width
   Otherwise `&[1u8, 0u8]` cannot be distinguished from `&[0x10u8]` (they both become 10)

### Other

 - <csr-id-02d1db5fc043fb7af90c14d13de6419ec5b9bcb5/> remove unwrap and NonZero* in info
   Addresses the feedback from #1007:
   - remove panic from `unwrap` and `expect`
   - Option<NonZero*> => Option<int> with `0` mapping to `None`
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
 - <csr-id-a75fc2f7691dad21822c2eff35281abd3c4b5d23/> Allow logging `core::net::Ipv4Addr` and `core::net::Ipv6Addr`
   IP address types are available in `core`, so they can be used also in
   eBPF programs. This change adds support of these types in aya-log.
   
   * Add implementation of `WriteTuBuf` to these types.
   * Support these types in `Ipv4Formatter` and `Ipv6Formatter`.
   * Support them with `DisplayHint::Ip`.
   * Add support for formatting `[u8; 4]`, to be able to handle
     `Ipv4Addr::octets`.
 - <csr-id-e66f9540c9196ecce16431542366771b6505124f/> allow re-attach and read previously created logs
   This feature is useful if someone wants to view the log contents
   of a program that is already running. For e.g. a pinned program
   or an XDP program attached to a net interface.

### Test

 - <csr-id-eef7346fb2231f8741410381198015cceeebfac9/> adjust test byte arrays for big endian
   Adding support for s390x (big endian architecture) and found that some
   of the unit tests have structures and files implemented as byte arrays.
   They are all coded as little endian and need a bug endian version to
   work properly.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 20 commits contributed to the release.
 - 223 days passed between releases.
 - 11 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 1 unique issue was worked on: [#1008](https://github.com/aya-rs/aya/issues/1008)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#1008](https://github.com/aya-rs/aya/issues/1008)**
    - Print &[u8] using full width ([`55ed9e0`](https://github.com/aya-rs/aya/commit/55ed9e054665ba303e1fb381c7ac590056da7724))
 * **Uncategorized**
    - Release aya-log-common v0.1.15, aya-log-ebpf v0.1.1 ([`04bbbcc`](https://github.com/aya-rs/aya/commit/04bbbccffa6298dbfeb967ca9967611e283ac81d))
    - Release aya-obj v0.2.0, aya v0.13.0, safety bump aya v0.13.0 ([`c169b72`](https://github.com/aya-rs/aya/commit/c169b727e6b8f8c2dda57f54b8c77f8b551025c6))
    - Reduce duplication in `{nr,possible}_cpus` ([`f3b2744`](https://github.com/aya-rs/aya/commit/f3b27440725a0eb2f1615c92cb0047e3b1548d66))
    - Remove unwrap and NonZero* in info ([`02d1db5`](https://github.com/aya-rs/aya/commit/02d1db5fc043fb7af90c14d13de6419ec5b9bcb5))
    - Merge pull request #1007 from tyrone-wu/aya/info-api ([`15eb935`](https://github.com/aya-rs/aya/commit/15eb935bce6d41fb67189c48ce582b074544e0ed))
    - Revamp MapInfo be more friendly with older kernels ([`fbb0930`](https://github.com/aya-rs/aya/commit/fbb09304a2de0d8baf7ea20c9727fcd2e4fb7f41))
    - Revamp ProgramInfo be more friendly with older kernels ([`88f5ac3`](https://github.com/aya-rs/aya/commit/88f5ac31142f1657b41b1ee0f217dcd9125b210a))
    - Merge pull request #974 from Billy99/billy99-arch-ppc64-s390x ([`ab5e688`](https://github.com/aya-rs/aya/commit/ab5e688fd49fcfb402ad47d51cb445437fbd8cb7))
    - Adjust test byte arrays for big endian ([`eef7346`](https://github.com/aya-rs/aya/commit/eef7346fb2231f8741410381198015cceeebfac9))
    - Revert "Remove unused `allow(dead_code)`" ([`4161993`](https://github.com/aya-rs/aya/commit/41619933d64289bec02c6672bd2248a8075eff3e))
    - Remove unused `allow(dead_code)` ([`5397c1c`](https://github.com/aya-rs/aya/commit/5397c1ca4b77cd27082e96aab9ab931631df7fa8))
    - Allow logging `core::net::Ipv4Addr` and `core::net::Ipv6Addr` ([`a75fc2f`](https://github.com/aya-rs/aya/commit/a75fc2f7691dad21822c2eff35281abd3c4b5d23))
    - Merge pull request #900 from catalin-h/log_init_from_program_id ([`e5d107d`](https://github.com/aya-rs/aya/commit/e5d107dd50b13ccf9783b9af4e79b57b02c1f0f3))
    - Reword rustdocs a bit ([`8830c0b`](https://github.com/aya-rs/aya/commit/8830c0bc20c6e3dbbddf63533d4623fcd45dd9af))
    - Allow re-attach and read previously created logs ([`e66f954`](https://github.com/aya-rs/aya/commit/e66f9540c9196ecce16431542366771b6505124f))
    - Merge pull request #528 from dave-tucker/rename-all-the-things ([`63d8d4d`](https://github.com/aya-rs/aya/commit/63d8d4d34bdbbee149047dc0a5e9c2b191f3b32d))
    - Rename Bpf to Ebpf ([`8c79b71`](https://github.com/aya-rs/aya/commit/8c79b71bd5699a686f33360520aa95c1a2895fa5))
    - Rename BpfLogger to EbpfLogger ([`a93e354`](https://github.com/aya-rs/aya/commit/a93e3546204115631c11bc0601905c205bf8a584))
    - Rename bpf -> ebpf ([`41c6156`](https://github.com/aya-rs/aya/commit/41c61560eae01a30c703ea22c5bfeeff0ecf6b1b))
</details>

## v0.2.0 (2024-02-28)

<csr-id-13b1fc63ef2ae083ba03ce9de24cb4f31f989d21/>
<csr-id-b3e7ef741c5b8d09fc7dc8302576f8174be75ff4/>
<csr-id-d16e607fd4b6258b516913071fdacafeb2bbbff9/>
<csr-id-ca3f70b16a705bf26d2ccc7ce754de403be36223/>
<csr-id-96fa08bd82233268154edf30b106876f5a4f0e30/>
<csr-id-c8bf646ef098a00bc5c6e1cb5ae35ffa6fb5eac5/>
<csr-id-84e5e2894f226f4b2c7cb637a6f44d5773b927e6/>
<csr-id-d9f966ec9e49f4439710559cac852bde62810975/>
<csr-id-e4537e389ad7ac6f09fc89349444e37fe01e4af4/>
<csr-id-5603d7248a51a16233c249b645e30ea3f6804744/>
<csr-id-1c8088b16cc255fc188b0b9a84b550a5c50a9003/>

### Chore

- <csr-id-13b1fc63ef2ae083ba03ce9de24cb4f31f989d21/> Don't use path deps in workspace
  This moves the path dependencies back into the per-crate Cargo.toml.
  It is required such that the release tooling can correctly calculate
  which version constraints require changing when we perform a release.
- <csr-id-b3e7ef741c5b8d09fc7dc8302576f8174be75ff4/> Use the cargo workspace package table
  This allows for inheritance of common fields from the workspace root.
  The following fields have been made common:

  - authors
  - license
  - repository
  - homepage
  - edition

### Documentation

 - <csr-id-9abb7160e51dd18c509049b1371acd96515d8f04/> Add CHANGELOG

### New Features

 - <csr-id-0970300d1f5659622fa55a18dd7681c608d75b0f/> check format and value type in proc macro

### Bug Fixes

 - <csr-id-d999a95b410df79e1d9f6c27462e19a2cede06c2/> remove some useless code

### Other

- <csr-id-d16e607fd4b6258b516913071fdacafeb2bbbff9/> group_imports = "StdExternalCrate"
  High time we stop debating this; let the robots do the work.
- <csr-id-ca3f70b16a705bf26d2ccc7ce754de403be36223/> s/Result<usize, ()>/Option<NonZeroUsize>/
  `Option<NonZeroUsize>` is guaranteed to have the same size as `usize`,
  which is not guarnateed for `Result`. This is a minor optimization, but
  also results in simpler code.
- <csr-id-96fa08bd82233268154edf30b106876f5a4f0e30/> Define dependencies on the workspace level
  This way we will avoid version mismatches and make differences in
  features across our crates clearer.
- <csr-id-c8bf646ef098a00bc5c6e1cb5ae35ffa6fb5eac5/> add formatter and check in CI
- <csr-id-84e5e2894f226f4b2c7cb637a6f44d5773b927e6/> Unify IP format hints into one, repsesent it by `:i` token
  Having separate format hints and tokens per IP address family is
  unnecessary, since they are represented by different types and we handle
  format hints for each type separately. So we can just have one format
  hint.

  Also, we should be consistent with the format strings grammar in
  Rust[0]. The `type` token, which is mapped to formatting traits, usually
  consists of one letter[1] (and optional `?` for `Debug` trait, but that
  doesn't matter for us). It shouldn't consist of multiple letters. Our
  `:ipv4` and `:ipv6` tokens were clearly breaking that convention, so we
  should rather switch to something with one letter - hence `:i`.

  [0] https://doc.rust-lang.org/std/fmt/#syntax
  [1] https://doc.rust-lang.org/std/fmt/#formatting-traits

- <csr-id-d9f966ec9e49f4439710559cac852bde62810975/> support logging byte slices
  These only support LowerHex and UpperHex hints for now.
- <csr-id-e4537e389ad7ac6f09fc89349444e37fe01e4af4/> check errors in tests
- <csr-id-5603d7248a51a16233c249b645e30ea3f6804744/> Move the `Pod` implementations from aya-log-common to aya-log
  Keeping the `Pod` implementations and optional dependency on aya in
  aya-log-common breaks the clippy checks (which are made on the entire
  workspace).

  The reason is that when different crates inside the workspace have the
  same dependency with different features, that dependency is built only
  once with the sum of features needed by all crates. It's **not** being
  built separately with different feature sets.

  That's why, before this change, aya-log-common was built once for the
  entire workspace with `userspace` feature enabled. That made importing
  aya-log-ebpf inside integration-ebpf impossible. The aya-log-common
  build, with `userspace` feature enabled, was pulling std as a
  dependency. Therefore, importing aya-log-ebpf inside integration-ebpf
  resulted in including std and errors like:

  ```
  error[E0152]: found duplicate lang item `panic_impl`
    --> test/integration-ebpf/src/log.rs:23:1
     |
  23 | fn panic(_info: &core::panic::PanicInfo) -> ! {
     | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     |
     = note: the lang item is first defined in crate `std` (which `aya` depends on)
  ```

  This change fixes the problem by removing the `userspace` feature from
  aya-log-common and moving the `Pod` implementations to aya-log.

- <csr-id-1c8088b16cc255fc188b0b9a84b550a5c50a9003/> update env_logger requirement from 0.9 to 0.10
  Updates the requirements on [env_logger](https://github.com/rust-cli/env_logger) to permit the latest version.

  - [Release notes](https://github.com/rust-cli/env_logger/releases)
  - [Changelog](https://github.com/rust-cli/env_logger/blob/main/CHANGELOG.md)
  - [Commits](https://github.com/rust-cli/env_logger/compare/v0.9.0...v0.10.0)

  ***

  updated-dependencies:

  - dependency-name: env_logger
    dependency-type: direct:production
    ...

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 38 commits contributed to the release.
 - 469 days passed between releases.
 - 14 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release aya-log-common v0.1.14, aya-log v0.2.0 ([`b6a84b6`](https://github.com/aya-rs/aya/commit/b6a84b658ae00f23d0f1721c30d11f2e57f99eab))
    - Add CHANGELOG ([`9abb716`](https://github.com/aya-rs/aya/commit/9abb7160e51dd18c509049b1371acd96515d8f04))
    - Release aya-log-common v0.1.14, aya-log v0.2.0 ([`c22a696`](https://github.com/aya-rs/aya/commit/c22a6963d44befb5591d4b21c09767c43935cb54))
    - Release aya-obj v0.1.0, aya v0.12.0, safety bump aya-log v0.2.0 ([`0e99fa0`](https://github.com/aya-rs/aya/commit/0e99fa0f340b2fb2e0da3b330aa6555322a77eec))
    - Don't use path deps in workspace ([`13b1fc6`](https://github.com/aya-rs/aya/commit/13b1fc63ef2ae083ba03ce9de24cb4f31f989d21))
    - Merge pull request #882 from dave-tucker/metadata ([`0fadd69`](https://github.com/aya-rs/aya/commit/0fadd695377b8a3f0d9a3af3bc8140f0f1bed8d2))
    - Use the cargo workspace package table ([`b3e7ef7`](https://github.com/aya-rs/aya/commit/b3e7ef741c5b8d09fc7dc8302576f8174be75ff4))
    - Appease rustc dead_code lint ([`963dd13`](https://github.com/aya-rs/aya/commit/963dd1321925c95f80c8a2bf656b88a39497ca01))
    - Merge pull request #797 from aya-rs/rustfmt-group-imports ([`373fb7b`](https://github.com/aya-rs/aya/commit/373fb7bf06ba80ee4c120d8c112f5e810204c472))
    - Group_imports = "StdExternalCrate" ([`d16e607`](https://github.com/aya-rs/aya/commit/d16e607fd4b6258b516913071fdacafeb2bbbff9))
    - Merge pull request #736 from aya-rs/logging-better ([`45df251`](https://github.com/aya-rs/aya/commit/45df2519b60613310e8827fbb4076f60c393c3bb))
    - Merge pull request #735 from aya-rs/log-option-not-result ([`ecf0dd9`](https://github.com/aya-rs/aya/commit/ecf0dd973985bd442978b202d0fd6f75647cdda3))
    - S/Result<usize, ()>/Option<NonZeroUsize>/ ([`ca3f70b`](https://github.com/aya-rs/aya/commit/ca3f70b16a705bf26d2ccc7ce754de403be36223))
    - Remove pointless DefaultLogger ([`00d265c`](https://github.com/aya-rs/aya/commit/00d265c51b69e672457502593fbc63d0ac953e27))
    - Merge pull request #667 from vadorovsky/workspace-dependencies ([`f554d42`](https://github.com/aya-rs/aya/commit/f554d421053bc34266afbf8e00b28705ab4b41d2))
    - Define dependencies on the workspace level ([`96fa08b`](https://github.com/aya-rs/aya/commit/96fa08bd82233268154edf30b106876f5a4f0e30))
    - Merge pull request #666 from aya-rs/toml-fmt ([`dc3b0b8`](https://github.com/aya-rs/aya/commit/dc3b0b87308fdac5ff8f472de9a5e849b52d9fee))
    - Add formatter and check in CI ([`c8bf646`](https://github.com/aya-rs/aya/commit/c8bf646ef098a00bc5c6e1cb5ae35ffa6fb5eac5))
    - Merge pull request #650 from aya-rs/test-cleanup ([`61608e6`](https://github.com/aya-rs/aya/commit/61608e64583f9dc599eef9b8db098f38a765b285))
    - Remove "async" feature ([`fa91fb4`](https://github.com/aya-rs/aya/commit/fa91fb4f59be3505664f8088b6e3e8da2c372253))
    - Unify IP format hints into one, repsesent it by `:i` token ([`84e5e28`](https://github.com/aya-rs/aya/commit/84e5e2894f226f4b2c7cb637a6f44d5773b927e6))
    - Remove some useless code ([`d999a95`](https://github.com/aya-rs/aya/commit/d999a95b410df79e1d9f6c27462e19a2cede06c2))
    - Check format and value type in proc macro ([`0970300`](https://github.com/aya-rs/aya/commit/0970300d1f5659622fa55a18dd7681c608d75b0f))
    - Merge pull request #585 from probulate/tag-len-value ([`5165bf2`](https://github.com/aya-rs/aya/commit/5165bf2f99cdc228122bdab505c2059723e95a9f))
    - Support logging byte slices ([`d9f966e`](https://github.com/aya-rs/aya/commit/d9f966ec9e49f4439710559cac852bde62810975))
    - Aya-log, aya-log-common: economize bytes ([`a4a69a6`](https://github.com/aya-rs/aya/commit/a4a69a6bcfe87d3c066f2cc341b74039f53dcc9e))
    - Check errors in tests ([`e4537e3`](https://github.com/aya-rs/aya/commit/e4537e389ad7ac6f09fc89349444e37fe01e4af4))
    - Aya-log, aya-log-common: Remove duplicate struct ([`490d7d5`](https://github.com/aya-rs/aya/commit/490d7d587ad90b899aff2a30d65db8641ceb32df))
    - Merge pull request #591 from vadorovsky/aya-log-impl-pod ([`3d3ce8b`](https://github.com/aya-rs/aya/commit/3d3ce8bfa2eff19706cc3d8e5f0ce9e81a520a78))
    - Move the `Pod` implementations from aya-log-common to aya-log ([`5603d72`](https://github.com/aya-rs/aya/commit/5603d7248a51a16233c249b645e30ea3f6804744))
    - Merge pull request #484 from vadorovsky/update-tokio ([`bea0e83`](https://github.com/aya-rs/aya/commit/bea0e83512cc6d45b3e4fb5c3f62432c434139b7))
    - Update Tokio and inventory ([`dad75f4`](https://github.com/aya-rs/aya/commit/dad75f45ac357e86eebc92c4f95f6dd4e43d8496))
    - Don't panic in init when bpf programs don't log ([`12927cf`](https://github.com/aya-rs/aya/commit/12927cf6992bc0f8b1e4221d48b34f4c0098b93d))
    - Merge pull request #456 from dmitris/uninlined_format_args ([`16b029e`](https://github.com/aya-rs/aya/commit/16b029ed3708470afd2a6d67615b30c8d30b5059))
    - Fix uninlined_format_args clippy issues ([`055d94f`](https://github.com/aya-rs/aya/commit/055d94f58be4f80ada416b99278a22f600c71285))
    - Merge pull request #449 from aya-rs/dependabot/cargo/env_logger-0.10 ([`f9bef9f`](https://github.com/aya-rs/aya/commit/f9bef9f8c0d2c5b21809e037b8e9782f3c761df3))
    - Update env_logger requirement from 0.9 to 0.10 ([`1c8088b`](https://github.com/aya-rs/aya/commit/1c8088b16cc255fc188b0b9a84b550a5c50a9003))
    - Revert "aya-log, aya-log-common: temporarily revert to old map API so we can release" ([`0b41018`](https://github.com/aya-rs/aya/commit/0b41018ee27bfda9b1ea7dc422b34d3a08fc3fc6))
</details>

## v0.1.13 (2022-11-16)

<csr-id-832bdd280c19095d79ba2d27281c17f0b09adc15/>
<csr-id-2223ab828d6db40a85cff4737f6164ed8ee9e42d/>
<csr-id-b2924a3a264732e6de6898a1f03d7cb22d1d0dc5/>
<csr-id-83ec27f06b6859f455f2b2baf985b8fd3fb4adc5/>
<csr-id-b8b291c51ba1b43ff27c6aab6b55d6af77334aae/>
<csr-id-611f967cd14b90e187ca86735f2131fb87e89856/>
<csr-id-6aea88089087194c831b259a61eef5ccebcb45bc/>
<csr-id-5789585994776d18afa58f3bb816cfcb1367298e/>
<csr-id-628b473e0937eef94b0b337608a5d6c51ad2fd2a/>
<csr-id-70b4e681301eb23ca776cd703e11f19cc879ac69/>
<csr-id-d1a0ce51ee4e67cf9b03b695940f356ee950f8c2/>
<csr-id-c4d89fa13cb4e96a62ccd5cae7cf1834c3c582f6/>
<csr-id-bdb2750e66f922ebfbcba7250add38e2c932c293/>
<csr-id-7f8d7057df11f41d0869f7f713d121785934adca/>

### Other

- <csr-id-832bdd280c19095d79ba2d27281c17f0b09adc15/> release version 0.1.13
- <csr-id-2223ab828d6db40a85cff4737f6164ed8ee9e42d/> Add format hints for MAC addresses
  Add `{:mac}` (for lower-case hex representation) and `{:MAC}` (for
  upper-case hex representation) format hints for the `[u8; 6]` type,
  which is the standard one in Linux to store physical addresses in.

  Tested with: https://github.com/vadorovsky/aya-examples/tree/main/xdp-mac

- <csr-id-b2924a3a264732e6de6898a1f03d7cb22d1d0dc5/> Make miri happy
  Miri took issue about using slice::from_raw_parts without checking for
  alignment. Instead, we can simply convert to a [u8;16] into a [u16;8] by
  iterating in chunks of 2 and bitshifting (remembering that these arrays
  are in network-endian order).
- <csr-id-83ec27f06b6859f455f2b2baf985b8fd3fb4adc5/> Add display hints
  This change adds optional display hints:

  - `{:x}`, `{:X}` - for hex representation of numbers
  - `{:ipv4}`, `{:IPv4}` - for IPv4 addresses
  - `{:ipv6}`, `{:IPv6}` - for IPv6 addresses

  It also gets rid of dyn-fmt and instead comes with our own parser
  implementation.

  Tested on: https://github.com/vadorovsky/aya-examples/tree/main/tc

- <csr-id-b8b291c51ba1b43ff27c6aab6b55d6af77334aae/> Fix links to aya-log repo
  The aya-log repo ([0]) has been archived, use the link to
  aya repo instead.
- <csr-id-611f967cd14b90e187ca86735f2131fb87e89856/> Remove i128 and u128 types
  They are not supported by eBPF VM and we are going to use arrays for
  IPv6.
- <csr-id-6aea88089087194c831b259a61eef5ccebcb45bc/> use new PerCpuArray::get_ptr_mut API
- <csr-id-5789585994776d18afa58f3bb816cfcb1367298e/> Add example
  This ensures that macro expansion works properly and that expanded code
  compiles
- <csr-id-628b473e0937eef94b0b337608a5d6c51ad2fd2a/> Ensure the bounds of log buffer
  eBPF verifier rejects programs which are not checking the bounds of the
  log buffer before writing any arguments. This change ensures that
  written log arguments.

  In practice, it means that doing this kind of checks is not going to be
  needed in eBPF program code anymore:

- <csr-id-70b4e681301eb23ca776cd703e11f19cc879ac69/> Bump the buffer size
  1024 is too small for many kernel string limits (i.e. PATH_MAX, which is
  4096).
- <csr-id-d1a0ce51ee4e67cf9b03b695940f356ee950f8c2/> do not release
- <csr-id-c4d89fa13cb4e96a62ccd5cae7cf1834c3c582f6/> use stricter version for the aya-log-common dep
- <csr-id-bdb2750e66f922ebfbcba7250add38e2c932c293/> inline write_record_header
  This seems to help the verifier keep track of where we're writing into
  LOG_BUF
- <csr-id-7f8d7057df11f41d0869f7f713d121785934adca/> initialize AYA_LOGS with max_entries=0
  This way aya will create one perf buffer for each cpu

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 59 commits contributed to the release.
 - 14 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release version 0.1.13 ([`832bdd2`](https://github.com/aya-rs/aya/commit/832bdd280c19095d79ba2d27281c17f0b09adc15))
    - Aya-log, aya-log-common: temporarily revert to old map API so we can release ([`0d040d2`](https://github.com/aya-rs/aya/commit/0d040d2290cc1513c979c95538210abd7ee59ebb))
    - Merge pull request #436 from vadorovsky/aya-log-mac-addr ([`3adb9b0`](https://github.com/aya-rs/aya/commit/3adb9b049f493ec9b80fcf868a8eac3363d17844))
    - Add format hints for MAC addresses ([`2223ab8`](https://github.com/aya-rs/aya/commit/2223ab828d6db40a85cff4737f6164ed8ee9e42d))
    - Merge pull request #397 from astoycos/refactor-map-api2 ([`d6cb1a1`](https://github.com/aya-rs/aya/commit/d6cb1a16ad0f8df483e2234fb01ab55bdbeaa8b8))
    - Make map APIs return an option ([`f3262e8`](https://github.com/aya-rs/aya/commit/f3262e87bd6ff895537df47fcf5d17c598e564cc))
    - Core refactor of Map API ([`1aefa2e`](https://github.com/aya-rs/aya/commit/1aefa2e5e6d22a600cc7339d289d64ab06f842e3))
    - Merge pull request #390 from dave-tucker/clippy-up ([`367ab20`](https://github.com/aya-rs/aya/commit/367ab203057329ea32eea34ddc97452e0c03fda6))
    - Make miri happy ([`b2924a3`](https://github.com/aya-rs/aya/commit/b2924a3a264732e6de6898a1f03d7cb22d1d0dc5))
    - Aya-log, aya-log-common: start next development iteration 0.1.12-dev.0 ([`6f0637a`](https://github.com/aya-rs/aya/commit/6f0637a6c8f3696b226558dc47b2dc2f6680e347))
    - Aya-log, aya-log-common: release version 0.1.11 ([`ba927ac`](https://github.com/aya-rs/aya/commit/ba927ac20497fdfd0033fb48f4bfda3fc8dedf42))
    - Add display hints ([`83ec27f`](https://github.com/aya-rs/aya/commit/83ec27f06b6859f455f2b2baf985b8fd3fb4adc5))
    - Change from Rust edition 2018 to 2021 ([`944d6b8`](https://github.com/aya-rs/aya/commit/944d6b8a1647df36c17cd060b15c37ac9615f4a7))
    - Merge pull request #361 from chenhengqi/fix-aya-log-links ([`632ea30`](https://github.com/aya-rs/aya/commit/632ea300ed8dcb3a277447a57b528b8d89b0c10a))
    - Fix links to aya-log repo ([`b8b291c`](https://github.com/aya-rs/aya/commit/b8b291c51ba1b43ff27c6aab6b55d6af77334aae))
    - Merge pull request #357 from vadorovsky/env_logger ([`3d5ab0b`](https://github.com/aya-rs/aya/commit/3d5ab0b17de0e4f1453a88ed00823d04db0845a6))
    - Aya-log, test: Switch from simplelog to env_logger ([`3664e1e`](https://github.com/aya-rs/aya/commit/3664e1ea0d42985bd88129cfd338bacff2456398))
    - Merge pull request #353 from vadorovsky/log-remove-u128 ([`d968094`](https://github.com/aya-rs/aya/commit/d968094b662be3449624420b76ea2dd239ef657b))
    - Remove i128 and u128 types ([`611f967`](https://github.com/aya-rs/aya/commit/611f967cd14b90e187ca86735f2131fb87e89856))
    - Merge pull request #350 from dave-tucker/monorepo ([`f37a514`](https://github.com/aya-rs/aya/commit/f37a51433ff5283205ba5d1e74cdc75fbdeea160))
    - Re-organize into a single workspace ([`dc31e11`](https://github.com/aya-rs/aya/commit/dc31e11691bbb8ae916da9da873fdc37ff261c27))
    - Fix the log buffer bounds ([`28abaec`](https://github.com/aya-rs/aya/commit/28abaece2af732cf2b2b2f8b12aeb02439e76d4c))
    - Ensure log buffer bounds ([`2e07028`](https://github.com/aya-rs/aya/commit/2e0702854b0e2428f6b5b32678f5f79ca341c619))
    - Use new PerCpuArray::get_ptr_mut API ([`6aea880`](https://github.com/aya-rs/aya/commit/6aea88089087194c831b259a61eef5ccebcb45bc))
    - Aya-log, aya-log-common: start next development iteration 0.1.11-dev.0 ([`526493b`](https://github.com/aya-rs/aya/commit/526493b444ed91f1c315ace494b41b8f4178fe65))
    - Aya-log, aya-log-common: release version 0.1.10 ([`3abd973`](https://github.com/aya-rs/aya/commit/3abd97307ef32bfbd384f38f7a0de40cc7afa0b1))
    - Update aya requirement from 0.10.7 to 0.11.0 ([`060ba45`](https://github.com/aya-rs/aya/commit/060ba451535b1a90c2faaf2dcd634fa36e784efb))
    - Add CI ([`0038b43`](https://github.com/aya-rs/aya/commit/0038b43627e6564b03d9837f535ec64ada6d70f2))
    - Add vim/vscode rust-analyzer settings ([`c1bb790`](https://github.com/aya-rs/aya/commit/c1bb790c0d8d467ac41603b15b56823c7ba0f663))
    - Add rustfmt.toml ([`3f00851`](https://github.com/aya-rs/aya/commit/3f0085195f178fdba6c214b4129f8321e612d4e7))
    - Add example ([`5789585`](https://github.com/aya-rs/aya/commit/5789585994776d18afa58f3bb816cfcb1367298e))
    - Add Tests ([`5d82d9a`](https://github.com/aya-rs/aya/commit/5d82d9a73e77d386c8be3dc3764b3dd361fcac71))
    - Ensure the bounds of log buffer ([`628b473`](https://github.com/aya-rs/aya/commit/628b473e0937eef94b0b337608a5d6c51ad2fd2a))
    - Bump the buffer size ([`70b4e68`](https://github.com/aya-rs/aya/commit/70b4e681301eb23ca776cd703e11f19cc879ac69))
    - Aya-log, aya-log-common: start next development iteration 0.1.10-dev.0 ([`bd9a5c8`](https://github.com/aya-rs/aya/commit/bd9a5c8fdff9c20952137908388b1d833ab60fcc))
    - Aya-log, aya-log-common: release version 0.1.9 ([`8bc1bbb`](https://github.com/aya-rs/aya/commit/8bc1bbb3abe588e89161e67ad013c34f1ec3ab6d))
    - Add cargo-release config ([`a8d133f`](https://github.com/aya-rs/aya/commit/a8d133f6b0919bb7d8e821f1309ee264d8b03a71))
    - Do not release ([`d1a0ce5`](https://github.com/aya-rs/aya/commit/d1a0ce51ee4e67cf9b03b695940f356ee950f8c2))
    - Use stricter version for the aya-log-common dep ([`c4d89fa`](https://github.com/aya-rs/aya/commit/c4d89fa13cb4e96a62ccd5cae7cf1834c3c582f6))
    - Inline write_record_header ([`bdb2750`](https://github.com/aya-rs/aya/commit/bdb2750e66f922ebfbcba7250add38e2c932c293))
    - Update aya to 0.10.7 ([`81befa0`](https://github.com/aya-rs/aya/commit/81befa06610b9e771523bceee4871a704851b1f0))
    - Format arguments in userspace ([`ca1fe7e`](https://github.com/aya-rs/aya/commit/ca1fe7e05f7b52c5e864680abeda29e640617d40))
    - Don't recompute the record length ([`9b229d0`](https://github.com/aya-rs/aya/commit/9b229d00e110a5b3b610ad567f8d15682c0b78e1))
    - Initialize AYA_LOGS with max_entries=0 ([`7f8d705`](https://github.com/aya-rs/aya/commit/7f8d7057df11f41d0869f7f713d121785934adca))
    - Fix clippy warning ([`2800454`](https://github.com/aya-rs/aya/commit/2800454763f5f0250c46c87f9cfb2e3d1f5f0a7e))
    - Add copy of README.md inside aya-log/ ([`8bde15d`](https://github.com/aya-rs/aya/commit/8bde15dad70016f6fb72a77906da341768d59720))
    - Add missing manifest fields ([`5e18a71`](https://github.com/aya-rs/aya/commit/5e18a715b2d1cf153de96d9775dfea762c684258))
    - (cargo-release) version 0.1.1 ([`31e71f8`](https://github.com/aya-rs/aya/commit/31e71f8db53454ce673bd9891be06fc002af5721))
    - (cargo-release) version 0.1.1 ([`29955b2`](https://github.com/aya-rs/aya/commit/29955b22875b865f567079c76aeba70630fa42dd))
    - Git add .cargo and xtask ([`6d14a16`](https://github.com/aya-rs/aya/commit/6d14a16d8ed54d90e9dfdbdca1fb2caf0a15c017))
    - Update to aya 0.10.5 ([`cced3da`](https://github.com/aya-rs/aya/commit/cced3da5c8ff45df0596e25123071a4a761286d6))
    - Simplify BpfLogger::init ([`9ab9c80`](https://github.com/aya-rs/aya/commit/9ab9c80183edcb23297a644d0e63f7c1f28cd968))
    - Minor tweaks to make the verifier's job easier ([`2ac4334`](https://github.com/aya-rs/aya/commit/2ac433449cdea32f10c8fc88218799995946032d))
    - Switch to aya-ufmt ([`b14d4ba`](https://github.com/aya-rs/aya/commit/b14d4bab2fac894d4e47838d7de8a9b63a5ac4c2))
    - Use aya_bpf::maps::PerfEventByteArray to output logs ([`22d8f86`](https://github.com/aya-rs/aya/commit/22d8f86fbb10ec5e71bca750119f93eb5ba171e5))
    - Use aya_log_ebpf::ufmt instead of ::ufmt ([`741957f`](https://github.com/aya-rs/aya/commit/741957f94598d149960a5296b2010a07ffac02e5))
    - Add ufmt to readme ([`0d7ac3e`](https://github.com/aya-rs/aya/commit/0d7ac3eb3ee58bd4ba10af9c49f7c9ef80e09143))
    - Update readme ([`5df853c`](https://github.com/aya-rs/aya/commit/5df853cfb030c3a37a066b892623546a77c97db2))
    - Initial commit ([`b29a061`](https://github.com/aya-rs/aya/commit/b29a061bce99d06971dc977ddc075cbf653971d4))
</details>

