# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.1.0 (2024-04-12)

<csr-id-13b1fc63ef2ae083ba03ce9de24cb4f31f989d21/>
<csr-id-b3e7ef741c5b8d09fc7dc8302576f8174be75ff4/>
<csr-id-2227223a96b0016ec960a8d5ba354d8c889ecc68/>
<csr-id-d16e607fd4b6258b516913071fdacafeb2bbbff9/>
<csr-id-ca3f70b16a705bf26d2ccc7ce754de403be36223/>
<csr-id-96fa08bd82233268154edf30b106876f5a4f0e30/>
<csr-id-6feebef9e551256156a8c22cf5de2165846a4793/>
<csr-id-de7972483b5b97c073b337568328a022378ebca9/>
<csr-id-47a2f25fca21e65d981b716d68f87af6203093d9/>
<csr-id-84e5e2894f226f4b2c7cb637a6f44d5773b927e6/>
<csr-id-4d098ef413dee3fe1cd260f19f7f90e69a06f06c/>
<csr-id-45072c078903a062f6aba4ed1562e0df091ee90e/>
<csr-id-2223ab828d6db40a85cff4737f6164ed8ee9e42d/>
<csr-id-9a8409e3a24179f4f60e6587b70e2ecd12322973/>
<csr-id-83ec27f06b6859f455f2b2baf985b8fd3fb4adc5/>

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

### Chore

 - <csr-id-1d515fe810c6e646ca405d8f97803698deda148c/> add missing changelogs

### New Features

 - <csr-id-0970300d1f5659622fa55a18dd7681c608d75b0f/> check format and value type in proc macro

### Other

 - <csr-id-2227223a96b0016ec960a8d5ba354d8c889ecc68/> fix hygiene
   Before this change we leaked some bindings to the calling scope, so for
   instance logging a variable named "len" led to a compile error.
 - <csr-id-d16e607fd4b6258b516913071fdacafeb2bbbff9/> group_imports = "StdExternalCrate"
   High time we stop debating this; let the robots do the work.
 - <csr-id-ca3f70b16a705bf26d2ccc7ce754de403be36223/> s/Result<usize, ()>/Option<NonZeroUsize>/
   `Option<NonZeroUsize>` is guaranteed to have the same size as `usize`,
   which is not guarnateed for `Result`. This is a minor optimization, but
   also results in simpler code.
 - <csr-id-96fa08bd82233268154edf30b106876f5a4f0e30/> Define dependencies on the workspace level
   This way we will avoid version mismatches and make differences in
   features across our crates clearer.
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
 - <csr-id-4d098ef413dee3fe1cd260f19f7f90e69a06f06c/> ensure WriteToBuf is used
   Previously any old `write` method could be selected.
 - <csr-id-45072c078903a062f6aba4ed1562e0df091ee90e/> update syn requirement from 1.0 to 2.0
   Updates the requirements on [syn](https://github.com/dtolnay/syn) to permit the latest version.
   - [Release notes](https://github.com/dtolnay/syn/releases)
   - [Commits](https://github.com/dtolnay/syn/compare/1.0.0...2.0.3)
   
   ---
   updated-dependencies:
   - dependency-name: syn
     dependency-type: direct:production
   ...
 - <csr-id-2223ab828d6db40a85cff4737f6164ed8ee9e42d/> Add format hints for MAC addresses
   Add `{:mac}` (for lower-case hex representation) and `{:MAC}` (for
   upper-case hex representation) format hints for the `[u8; 6]` type,
   which is the standard one in Linux to store physical addresses in.
   
   Tested with: https://github.com/vadorovsky/aya-examples/tree/main/xdp-mac
 - <csr-id-9a8409e3a24179f4f60e6587b70e2ecd12322973/> Fix the DisplayHint expression names
 - <csr-id-83ec27f06b6859f455f2b2baf985b8fd3fb4adc5/> Add display hints
   This change adds optional display hints:
   
   * `{:x}`, `{:X}` - for hex representation of numbers
   * `{:ipv4}`, `{:IPv4}` - for IPv4 addresses
   * `{:ipv6}`, `{:IPv6}` - for IPv6 addresses
   
   It also gets rid of dyn-fmt and instead comes with our own parser
   implementation.
   
   Tested on: https://github.com/vadorovsky/aya-examples/tree/main/tc

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 35 commits contributed to the release over the course of 623 calendar days.
 - 17 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release aya-log-parser v0.1.13 ([`04ee35d`](https://github.com/aya-rs/aya/commit/04ee35d1392ab7dc2d97c6e0f1449e98b1283ffe))
    - Add missing changelogs ([`1d515fe`](https://github.com/aya-rs/aya/commit/1d515fe810c6e646ca405d8f97803698deda148c))
    - Release aya-log-common v0.1.14, aya-log v0.2.0 ([`c22a696`](https://github.com/aya-rs/aya/commit/c22a6963d44befb5591d4b21c09767c43935cb54))
    - Don't use path deps in workspace ([`13b1fc6`](https://github.com/aya-rs/aya/commit/13b1fc63ef2ae083ba03ce9de24cb4f31f989d21))
    - Merge pull request #882 from dave-tucker/metadata ([`0fadd69`](https://github.com/aya-rs/aya/commit/0fadd695377b8a3f0d9a3af3bc8140f0f1bed8d2))
    - Use the cargo workspace package table ([`b3e7ef7`](https://github.com/aya-rs/aya/commit/b3e7ef741c5b8d09fc7dc8302576f8174be75ff4))
    - Fix hygiene ([`2227223`](https://github.com/aya-rs/aya/commit/2227223a96b0016ec960a8d5ba354d8c889ecc68))
    - Merge pull request #797 from aya-rs/rustfmt-group-imports ([`373fb7b`](https://github.com/aya-rs/aya/commit/373fb7bf06ba80ee4c120d8c112f5e810204c472))
    - Group_imports = "StdExternalCrate" ([`d16e607`](https://github.com/aya-rs/aya/commit/d16e607fd4b6258b516913071fdacafeb2bbbff9))
    - Merge pull request #735 from aya-rs/log-option-not-result ([`ecf0dd9`](https://github.com/aya-rs/aya/commit/ecf0dd973985bd442978b202d0fd6f75647cdda3))
    - S/Result<usize, ()>/Option<NonZeroUsize>/ ([`ca3f70b`](https://github.com/aya-rs/aya/commit/ca3f70b16a705bf26d2ccc7ce754de403be36223))
    - Merge pull request #683 from aya-rs/logs-wtf ([`5ebaf5f`](https://github.com/aya-rs/aya/commit/5ebaf5f39369289fbf4f6292dde2d697d45d3111))
    - Refactor log macro for readability ([`b3db916`](https://github.com/aya-rs/aya/commit/b3db9161eb304a4b83aa6122ebfc3d81fd4cd995))
    - Merge pull request #667 from vadorovsky/workspace-dependencies ([`f554d42`](https://github.com/aya-rs/aya/commit/f554d421053bc34266afbf8e00b28705ab4b41d2))
    - Define dependencies on the workspace level ([`96fa08b`](https://github.com/aya-rs/aya/commit/96fa08bd82233268154edf30b106876f5a4f0e30))
    - Merge pull request #611 from probulate/check-refs-not-values ([`3f1a469`](https://github.com/aya-rs/aya/commit/3f1a469f068a0af9bdb137796504a72163fb41cf))
    - Simplify argument validation ([`6feebef`](https://github.com/aya-rs/aya/commit/6feebef9e551256156a8c22cf5de2165846a4793))
    - Avoid requiring Copy ([`de79724`](https://github.com/aya-rs/aya/commit/de7972483b5b97c073b337568328a022378ebca9))
    - Fix compile errors ([`47a2f25`](https://github.com/aya-rs/aya/commit/47a2f25fca21e65d981b716d68f87af6203093d9))
    - Unify IP format hints into one, repsesent it by `:i` token ([`84e5e28`](https://github.com/aya-rs/aya/commit/84e5e2894f226f4b2c7cb637a6f44d5773b927e6))
    - Merge pull request #606 from Hanaasagi/check-format-in-log ([`58f1ecb`](https://github.com/aya-rs/aya/commit/58f1ecbf0089194d729327692adca6391fc24932))
    - Check format and value type in proc macro ([`0970300`](https://github.com/aya-rs/aya/commit/0970300d1f5659622fa55a18dd7681c608d75b0f))
    - Merge pull request #585 from probulate/tag-len-value ([`5165bf2`](https://github.com/aya-rs/aya/commit/5165bf2f99cdc228122bdab505c2059723e95a9f))
    - Ensure WriteToBuf is used ([`4d098ef`](https://github.com/aya-rs/aya/commit/4d098ef413dee3fe1cd260f19f7f90e69a06f06c))
    - Merge pull request #550 from aya-rs/dependabot/cargo/syn-2.0 ([`3ad3cb9`](https://github.com/aya-rs/aya/commit/3ad3cb9ed83f211bee2bfb68a2520f75b123d338))
    - Update syn requirement from 1.0 to 2.0 ([`45072c0`](https://github.com/aya-rs/aya/commit/45072c078903a062f6aba4ed1562e0df091ee90e))
    - Merge pull request #456 from dmitris/uninlined_format_args ([`16b029e`](https://github.com/aya-rs/aya/commit/16b029ed3708470afd2a6d67615b30c8d30b5059))
    - Fix uninlined_format_args clippy issues ([`055d94f`](https://github.com/aya-rs/aya/commit/055d94f58be4f80ada416b99278a22f600c71285))
    - Merge pull request #436 from vadorovsky/aya-log-mac-addr ([`3adb9b0`](https://github.com/aya-rs/aya/commit/3adb9b049f493ec9b80fcf868a8eac3363d17844))
    - Add format hints for MAC addresses ([`2223ab8`](https://github.com/aya-rs/aya/commit/2223ab828d6db40a85cff4737f6164ed8ee9e42d))
    - Fix the DisplayHint expression names ([`9a8409e`](https://github.com/aya-rs/aya/commit/9a8409e3a24179f4f60e6587b70e2ecd12322973))
    - Add display hints ([`83ec27f`](https://github.com/aya-rs/aya/commit/83ec27f06b6859f455f2b2baf985b8fd3fb4adc5))
    - Change from Rust edition 2018 to 2021 ([`944d6b8`](https://github.com/aya-rs/aya/commit/944d6b8a1647df36c17cd060b15c37ac9615f4a7))
    - Merge pull request #350 from dave-tucker/monorepo ([`f37a514`](https://github.com/aya-rs/aya/commit/f37a51433ff5283205ba5d1e74cdc75fbdeea160))
    - Re-organize into a single workspace ([`dc31e11`](https://github.com/aya-rs/aya/commit/dc31e11691bbb8ae916da9da873fdc37ff261c27))
</details>

