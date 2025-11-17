# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes

 - <csr-id-9be2d723ce5d7bf5f85d69d54aa5fd7f60d48edc/> Updated the shared types for the new ring-buffer transport used by `aya-log`, aligning the user- and eBPF-side structures.
 - <csr-id-214fe3c3673b182606c14d5e43f7f4ac512e47a7/> Sealed the `Argument` trait so downstream crates can no longer implement log argument types.

### New Features

 - <csr-id-a98b638fa95fd8edb8c015ee03154d2f03ecffc8/> Added support for logging raw pointer values, mirroring the new host-side formatting capabilities.

### Maintenance

 - <csr-id-0429ed2fa299636428b65573456cffe0aac2beca/>, <csr-id-5f5305c2a8ca0a739219093599dd57182d440ac1/> General lint, edition, and formatting cleanups to keep the crate in line with the workspace standards.

## 0.1.15 (2024-10-09)

<csr-id-a75fc2f7691dad21822c2eff35281abd3c4b5d23/>

### Other

 - <csr-id-a75fc2f7691dad21822c2eff35281abd3c4b5d23/> Allow logging `core::net::Ipv4Addr` and `core::net::Ipv6Addr`
   IP address types are available in `core`, so they can be used also in
   eBPF programs. This change adds support of these types in aya-log.
   
   * Add implementation of `WriteTuBuf` to these types.
   * Support these types in `Ipv4Formatter` and `Ipv6Formatter`.
   * Support them with `DisplayHint::Ip`.
   * Add support for formatting `[u8; 4]`, to be able to handle
     `Ipv4Addr::octets`.

### Chore

 - <csr-id-c3f0c7dc3fb285da091454426eeda0723389f0f1/> Prepare for aya-log-ebpf release

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 3 commits contributed to the release.
 - 223 days passed between releases.
 - 2 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Prepare for aya-log-ebpf release ([`c3f0c7d`](https://github.com/aya-rs/aya/commit/c3f0c7dc3fb285da091454426eeda0723389f0f1))
    - Allow logging `core::net::Ipv4Addr` and `core::net::Ipv6Addr` ([`a75fc2f`](https://github.com/aya-rs/aya/commit/a75fc2f7691dad21822c2eff35281abd3c4b5d23))
    - Appease clippy ([`09442c2`](https://github.com/aya-rs/aya/commit/09442c2cbe9513365dfc1df8d4f7cf6f808a67ed))
</details>

## v0.1.14 (2024-02-28)

<csr-id-b3e7ef741c5b8d09fc7dc8302576f8174be75ff4/>
<csr-id-b54a106584bf636cbd0ad217aa62124348e6b29f/>
<csr-id-ca3f70b16a705bf26d2ccc7ce754de403be36223/>
<csr-id-3cfd886dc512872fd3948cdf3baa8c99fe27ef0f/>
<csr-id-fe047d79a3f501631ae6406444769f6d5f6fed24/>
<csr-id-96fa08bd82233268154edf30b106876f5a4f0e30/>
<csr-id-c8bf646ef098a00bc5c6e1cb5ae35ffa6fb5eac5/>
<csr-id-6feebef9e551256156a8c22cf5de2165846a4793/>
<csr-id-de7972483b5b97c073b337568328a022378ebca9/>
<csr-id-47a2f25fca21e65d981b716d68f87af6203093d9/>
<csr-id-84e5e2894f226f4b2c7cb637a6f44d5773b927e6/>
<csr-id-d9f966ec9e49f4439710559cac852bde62810975/>
<csr-id-9a1a720a74fd458b4865e1139dd2f4ca84994ef2/>
<csr-id-5603d7248a51a16233c249b645e30ea3f6804744/>
<csr-id-b10a31183be12d44292ed2540225058499a938b1/>

### Chore

 - <csr-id-b3e7ef741c5b8d09fc7dc8302576f8174be75ff4/> Use the cargo workspace package table
   This allows for inheritance of common fields from the workspace root.
   The following fields have been made common:
   
   - authors
   - license
   - repository
   - homepage
   - edition

### Documentation

 - <csr-id-4f0f0957758362296c2d0a4749d354edd8dc181e/> Add CHANGELOG

### New Features

 - <csr-id-0970300d1f5659622fa55a18dd7681c608d75b0f/> check format and value type in proc macro

### Bug Fixes

 - <csr-id-d999a95b410df79e1d9f6c27462e19a2cede06c2/> remove some useless code

### Other

 - <csr-id-b54a106584bf636cbd0ad217aa62124348e6b29f/> update comments
   These were missed when the code was updated.
 - <csr-id-ca3f70b16a705bf26d2ccc7ce754de403be36223/> s/Result<usize, ()>/Option<NonZeroUsize>/
   `Option<NonZeroUsize>` is guaranteed to have the same size as `usize`,
   which is not guarnateed for `Result`. This is a minor optimization, but
   also results in simpler code.
 - <csr-id-3cfd886dc512872fd3948cdf3baa8c99fe27ef0f/> annotate logging functions inlining
   Some of these functions fail to compile when not inlined, so we should
   be explicit.
   
   Before deciding on this approach I tried various ways of making all
   these functions #[inline(never)] to save instructions but I ran into
   blockers:
   - These functions currently return Result, which is a structure. This is
     not permitted in BPF.
   - I tried inventing a newtype that is a #[repr(transparent)] wrapper of
     u16, and having these functions return that; however it seems that
     even if the object code is legal, the verifier will reject such
     functions because the BTF (if present, and it was in my local
     experiments) would indicate that the return is a structure.
   - I tried having these functions return a plain u16 where 0 means error,
     but the verifier still rejected the BTF because the receiver (even if
     made into &self) is considered a structure, and forbidden.
   
   We can eventually overcome these problems by "lying" in our BTF once
   support for it matures in the bpf-linker repo (e.g. Option<NonZeroU16>
   should be perfectly legal as it is guaranteed to be word-sized), but we
   aren't there yet, and this is the safest thing we can do for now.
 - <csr-id-fe047d79a3f501631ae6406444769f6d5f6fed24/> Simplify
   - Remove `TagLenValue`; this type has a single method, which is now a
     function.
   - Remove generics from `TagLenValue::write` (now `write`). The tag is
     always `u8`, and the value is always a sequence of bytes.
   - Replace slicing operations which can panic with calls to `get` which
     explicit check bounds.
 - <csr-id-96fa08bd82233268154edf30b106876f5a4f0e30/> Define dependencies on the workspace level
   This way we will avoid version mismatches and make differences in
   features across our crates clearer.
 - <csr-id-c8bf646ef098a00bc5c6e1cb5ae35ffa6fb5eac5/> add formatter and check in CI
 - <csr-id-6feebef9e551256156a8c22cf5de2165846a4793/> simplify argument validation
 - <csr-id-de7972483b5b97c073b337568328a022378ebca9/> avoid requiring Copy
   Before this change:
   ```
   error[E0382]: use of moved value: `no_copy`
     --> test/integration-ebpf/src/log.rs:35:9
      |
   33 |         let no_copy = NoCopy {};
      |             ------- move occurs because `no_copy` has type `NoCopy`, which does not implement the `Copy` trait
   34 |
   35 |         debug!(&ctx, "{:x}", no_copy.consume());
      |         ^^^^^^^^^^^^^^^^^^^^^-------^---------^
      |         |                    |       |
      |         |                    |       `no_copy` moved due to this method call
      |         |                    use occurs due to use in closure
      |         value used here after move
      |
   note: `NoCopy::consume` takes ownership of the receiver `self`, which moves `no_copy`
     --> test/integration-ebpf/src/log.rs:28:24
      |
   28 |             fn consume(self) -> u64 {
      |                        ^^^^
      = note: this error originates in the macro `debug` (in Nightly builds, run with -Z macro-backtrace for more info)
   
   For more information about this error, try `rustc --explain E0382`.
   error: could not compile `integration-ebpf` (bin "log") due to previous error
   ```
 - <csr-id-47a2f25fca21e65d981b716d68f87af6203093d9/> fix compile errors
   aya-log-ebpf-macros was failing to compile because it was referencing
   a couple of `DisplayHint` variants that no longer exist. These were
   removed in #599.
   
   ```
       Compiling aya-log-ebpf-macros v0.1.0 (/home/robert/aya/aya-log-ebpf-macros)
   error[E0599]: no variant or associated item named `Ipv4` found for enum `DisplayHint` in the current scope
     --> aya-log-ebpf-macros/src/expand.rs:93:22
      |
   93 |         DisplayHint::Ipv4 => parse_str("::aya_log_ebpf::macro_support::check_impl_ipv4"),
      |                      ^^^^ variant or associated item not found in `DisplayHint`
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
 - <csr-id-9a1a720a74fd458b4865e1139dd2f4ca84994ef2/> generalize TagLenValue
   This allows logging values backed by generators.
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
 - <csr-id-b10a31183be12d44292ed2540225058499a938b1/> update num_enum requirement from 0.5 to 0.6
   Updates the requirements on [num_enum](https://github.com/illicitonion/num_enum) to permit the latest version.
   - [Release notes](https://github.com/illicitonion/num_enum/releases)
   - [Commits](https://github.com/illicitonion/num_enum/compare/0.5.0...0.6.0)
   
   ---
   updated-dependencies:
   - dependency-name: num_enum
     dependency-type: direct:production
   ...

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 38 commits contributed to the release.
 - 469 days passed between releases.
 - 18 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release aya-log-common v0.1.14, aya-log v0.2.0 ([`b6a84b6`](https://github.com/aya-rs/aya/commit/b6a84b658ae00f23d0f1721c30d11f2e57f99eab))
    - Add CHANGELOG ([`4f0f095`](https://github.com/aya-rs/aya/commit/4f0f0957758362296c2d0a4749d354edd8dc181e))
    - Release aya-log-common v0.1.14, aya-log v0.2.0 ([`c22a696`](https://github.com/aya-rs/aya/commit/c22a6963d44befb5591d4b21c09767c43935cb54))
    - Merge pull request #882 from dave-tucker/metadata ([`0fadd69`](https://github.com/aya-rs/aya/commit/0fadd695377b8a3f0d9a3af3bc8140f0f1bed8d2))
    - Use the cargo workspace package table ([`b3e7ef7`](https://github.com/aya-rs/aya/commit/b3e7ef741c5b8d09fc7dc8302576f8174be75ff4))
    - Merge pull request #738 from aya-rs/kill-qemu-better ([`fbbf191`](https://github.com/aya-rs/aya/commit/fbbf191bd3b12fafd2fb17a527c4855277df5869))
    - Update comments ([`b54a106`](https://github.com/aya-rs/aya/commit/b54a106584bf636cbd0ad217aa62124348e6b29f))
    - Merge pull request #735 from aya-rs/log-option-not-result ([`ecf0dd9`](https://github.com/aya-rs/aya/commit/ecf0dd973985bd442978b202d0fd6f75647cdda3))
    - S/Result<usize, ()>/Option<NonZeroUsize>/ ([`ca3f70b`](https://github.com/aya-rs/aya/commit/ca3f70b16a705bf26d2ccc7ce754de403be36223))
    - Merge pull request #729 from aya-rs/logs-inline-always ([`84d5791`](https://github.com/aya-rs/aya/commit/84d5791d4e0623ffa5b7f6e4b1aa7d18a872f314))
    - Annotate logging functions inlining ([`3cfd886`](https://github.com/aya-rs/aya/commit/3cfd886dc512872fd3948cdf3baa8c99fe27ef0f))
    - Simplify ([`fe047d7`](https://github.com/aya-rs/aya/commit/fe047d79a3f501631ae6406444769f6d5f6fed24))
    - Merge pull request #667 from vadorovsky/workspace-dependencies ([`f554d42`](https://github.com/aya-rs/aya/commit/f554d421053bc34266afbf8e00b28705ab4b41d2))
    - Define dependencies on the workspace level ([`96fa08b`](https://github.com/aya-rs/aya/commit/96fa08bd82233268154edf30b106876f5a4f0e30))
    - Merge pull request #666 from aya-rs/toml-fmt ([`dc3b0b8`](https://github.com/aya-rs/aya/commit/dc3b0b87308fdac5ff8f472de9a5e849b52d9fee))
    - Add formatter and check in CI ([`c8bf646`](https://github.com/aya-rs/aya/commit/c8bf646ef098a00bc5c6e1cb5ae35ffa6fb5eac5))
    - Merge pull request #650 from aya-rs/test-cleanup ([`61608e6`](https://github.com/aya-rs/aya/commit/61608e64583f9dc599eef9b8db098f38a765b285))
    - Include ~all crates in default members ([`6d06e2b`](https://github.com/aya-rs/aya/commit/6d06e2bf3a6d267589339743fef694763b5cc5af))
    - Merge pull request #641 from aya-rs/logger-messages-plz ([`4c0983b`](https://github.com/aya-rs/aya/commit/4c0983bca962e0e9b2711805ae7fbc6b53457c34))
    - Add missing test annotation ([`7f25956`](https://github.com/aya-rs/aya/commit/7f25956aea94a2267dd721d94ad51625e109fe7f))
    - Merge pull request #611 from probulate/check-refs-not-values ([`3f1a469`](https://github.com/aya-rs/aya/commit/3f1a469f068a0af9bdb137796504a72163fb41cf))
    - Simplify argument validation ([`6feebef`](https://github.com/aya-rs/aya/commit/6feebef9e551256156a8c22cf5de2165846a4793))
    - Avoid requiring Copy ([`de79724`](https://github.com/aya-rs/aya/commit/de7972483b5b97c073b337568328a022378ebca9))
    - Fix compile errors ([`47a2f25`](https://github.com/aya-rs/aya/commit/47a2f25fca21e65d981b716d68f87af6203093d9))
    - Unify IP format hints into one, repsesent it by `:i` token ([`84e5e28`](https://github.com/aya-rs/aya/commit/84e5e2894f226f4b2c7cb637a6f44d5773b927e6))
    - Merge pull request #606 from Hanaasagi/check-format-in-log ([`58f1ecb`](https://github.com/aya-rs/aya/commit/58f1ecbf0089194d729327692adca6391fc24932))
    - Remove some useless code ([`d999a95`](https://github.com/aya-rs/aya/commit/d999a95b410df79e1d9f6c27462e19a2cede06c2))
    - Check format and value type in proc macro ([`0970300`](https://github.com/aya-rs/aya/commit/0970300d1f5659622fa55a18dd7681c608d75b0f))
    - Merge pull request #585 from probulate/tag-len-value ([`5165bf2`](https://github.com/aya-rs/aya/commit/5165bf2f99cdc228122bdab505c2059723e95a9f))
    - Support logging byte slices ([`d9f966e`](https://github.com/aya-rs/aya/commit/d9f966ec9e49f4439710559cac852bde62810975))
    - Generalize TagLenValue ([`9a1a720`](https://github.com/aya-rs/aya/commit/9a1a720a74fd458b4865e1139dd2f4ca84994ef2))
    - Aya-log, aya-log-common: economize bytes ([`a4a69a6`](https://github.com/aya-rs/aya/commit/a4a69a6bcfe87d3c066f2cc341b74039f53dcc9e))
    - Merge pull request #591 from vadorovsky/aya-log-impl-pod ([`3d3ce8b`](https://github.com/aya-rs/aya/commit/3d3ce8bfa2eff19706cc3d8e5f0ce9e81a520a78))
    - Move the `Pod` implementations from aya-log-common to aya-log ([`5603d72`](https://github.com/aya-rs/aya/commit/5603d7248a51a16233c249b645e30ea3f6804744))
    - Merge branch 'aya-rs:main' into lsm_sleepable ([`1f2006b`](https://github.com/aya-rs/aya/commit/1f2006bfde865cc4308643b21d51cf4a8e69d6d4))
    - Merge pull request #570 from aya-rs/dependabot/cargo/num_enum-0.6 ([`fcc8a0d`](https://github.com/aya-rs/aya/commit/fcc8a0d50da41103eb8b5190ff4253ec7510d39d))
    - Update num_enum requirement from 0.5 to 0.6 ([`b10a311`](https://github.com/aya-rs/aya/commit/b10a31183be12d44292ed2540225058499a938b1))
    - Revert "aya-log, aya-log-common: temporarily revert to old map API so we can release" ([`0b41018`](https://github.com/aya-rs/aya/commit/0b41018ee27bfda9b1ea7dc422b34d3a08fc3fc6))
</details>

## v0.1.13 (2022-11-16)

<csr-id-832bdd280c19095d79ba2d27281c17f0b09adc15/>
<csr-id-2223ab828d6db40a85cff4737f6164ed8ee9e42d/>
<csr-id-83ec27f06b6859f455f2b2baf985b8fd3fb4adc5/>
<csr-id-611f967cd14b90e187ca86735f2131fb87e89856/>

### Other

 - <csr-id-832bdd280c19095d79ba2d27281c17f0b09adc15/> release version 0.1.13
 - <csr-id-2223ab828d6db40a85cff4737f6164ed8ee9e42d/> Add format hints for MAC addresses
   Add `{:mac}` (for lower-case hex representation) and `{:MAC}` (for
   upper-case hex representation) format hints for the `[u8; 6]` type,
   which is the standard one in Linux to store physical addresses in.
   
   Tested with: https://github.com/vadorovsky/aya-examples/tree/main/xdp-mac
 - <csr-id-83ec27f06b6859f455f2b2baf985b8fd3fb4adc5/> Add display hints
   This change adds optional display hints:
   
   * `{:x}`, `{:X}` - for hex representation of numbers
   * `{:ipv4}`, `{:IPv4}` - for IPv4 addresses
   * `{:ipv6}`, `{:IPv6}` - for IPv6 addresses
   
   It also gets rid of dyn-fmt and instead comes with our own parser
   implementation.
   
   Tested on: https://github.com/vadorovsky/aya-examples/tree/main/tc
 - <csr-id-611f967cd14b90e187ca86735f2131fb87e89856/> Remove i128 and u128 types
   They are not supported by eBPF VM and we are going to use arrays for
   IPv6.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 12 commits contributed to the release.
 - 4 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release version 0.1.13 ([`832bdd2`](https://github.com/aya-rs/aya/commit/832bdd280c19095d79ba2d27281c17f0b09adc15))
    - Aya-log, aya-log-common: temporarily revert to old map API so we can release ([`0d040d2`](https://github.com/aya-rs/aya/commit/0d040d2290cc1513c979c95538210abd7ee59ebb))
    - Merge pull request #436 from vadorovsky/aya-log-mac-addr ([`3adb9b0`](https://github.com/aya-rs/aya/commit/3adb9b049f493ec9b80fcf868a8eac3363d17844))
    - Add format hints for MAC addresses ([`2223ab8`](https://github.com/aya-rs/aya/commit/2223ab828d6db40a85cff4737f6164ed8ee9e42d))
    - Aya-log, aya-log-common: start next development iteration 0.1.12-dev.0 ([`6f0637a`](https://github.com/aya-rs/aya/commit/6f0637a6c8f3696b226558dc47b2dc2f6680e347))
    - Aya-log, aya-log-common: release version 0.1.11 ([`ba927ac`](https://github.com/aya-rs/aya/commit/ba927ac20497fdfd0033fb48f4bfda3fc8dedf42))
    - Add display hints ([`83ec27f`](https://github.com/aya-rs/aya/commit/83ec27f06b6859f455f2b2baf985b8fd3fb4adc5))
    - Change from Rust edition 2018 to 2021 ([`944d6b8`](https://github.com/aya-rs/aya/commit/944d6b8a1647df36c17cd060b15c37ac9615f4a7))
    - Merge pull request #353 from vadorovsky/log-remove-u128 ([`d968094`](https://github.com/aya-rs/aya/commit/d968094b662be3449624420b76ea2dd239ef657b))
    - Remove i128 and u128 types ([`611f967`](https://github.com/aya-rs/aya/commit/611f967cd14b90e187ca86735f2131fb87e89856))
    - Merge pull request #350 from dave-tucker/monorepo ([`f37a514`](https://github.com/aya-rs/aya/commit/f37a51433ff5283205ba5d1e74cdc75fbdeea160))
    - Re-organize into a single workspace ([`dc31e11`](https://github.com/aya-rs/aya/commit/dc31e11691bbb8ae916da9da873fdc37ff261c27))
</details>

