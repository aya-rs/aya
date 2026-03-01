# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## v0.1.14 (2025-11-17)

### Improvements

 - <csr-id-1bf6a386197d019c0a548fdf488c9edf6c67c7e1/> Simplified the parser’s parameter handling so formatting errors are surfaced earlier and with clearer context.
 - <csr-id-a98b638fa95fd8edb8c015ee03154d2f03ecffc8/> Added raw-pointer format support to stay in sync with the new logging capabilities.

### Maintenance

 - <csr-id-f0a9f19ddc7f02143a02dcc2bf6be88fa2d84063/>, <csr-id-41706d74e44f2c3589c28a7149beb4db185594f2/> Bumped the edition and refreshed lint/formatting settings alongside the rest of the workspace.

## v0.1.13 (2024-04-12)

<csr-id-13b1fc63ef2ae083ba03ce9de24cb4f31f989d21/>
<csr-id-b3e7ef741c5b8d09fc7dc8302576f8174be75ff4/>
<csr-id-8e485bc77aaa49d41063853f83ab6017d334939e/>
<csr-id-96fa08bd82233268154edf30b106876f5a4f0e30/>
<csr-id-e08c6471dd351a1b717a38301a0ded5f04d1450d/>
<csr-id-84e5e2894f226f4b2c7cb637a6f44d5773b927e6/>
<csr-id-2223ab828d6db40a85cff4737f6164ed8ee9e42d/>
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

### Other

 - <csr-id-8e485bc77aaa49d41063853f83ab6017d334939e/> add support of :p format
 - <csr-id-96fa08bd82233268154edf30b106876f5a4f0e30/> Define dependencies on the workspace level
   This way we will avoid version mismatches and make differences in
   features across our crates clearer.
 - <csr-id-e08c6471dd351a1b717a38301a0ded5f04d1450d/> suppress resolver warning on nightly
   ```
   warning: some crates are on edition 2021 which defaults to `resolver = "2"`, but virtual workspaces default to `resolver = "1"`
   ```
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

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 18 commits contributed to the release over the course of 591 calendar days.
 - 9 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Add missing changelogs ([`1d515fe`](https://github.com/aya-rs/aya/commit/1d515fe810c6e646ca405d8f97803698deda148c))
    - Release aya-log-common v0.1.14, aya-log v0.2.0 ([`c22a696`](https://github.com/aya-rs/aya/commit/c22a6963d44befb5591d4b21c09767c43935cb54))
    - Don't use path deps in workspace ([`13b1fc6`](https://github.com/aya-rs/aya/commit/13b1fc63ef2ae083ba03ce9de24cb4f31f989d21))
    - Merge pull request #882 from dave-tucker/metadata ([`0fadd69`](https://github.com/aya-rs/aya/commit/0fadd695377b8a3f0d9a3af3bc8140f0f1bed8d2))
    - Use the cargo workspace package table ([`b3e7ef7`](https://github.com/aya-rs/aya/commit/b3e7ef741c5b8d09fc7dc8302576f8174be75ff4))
    - Add support of :p format ([`8e485bc`](https://github.com/aya-rs/aya/commit/8e485bc77aaa49d41063853f83ab6017d334939e))
    - Merge pull request #667 from vadorovsky/workspace-dependencies ([`f554d42`](https://github.com/aya-rs/aya/commit/f554d421053bc34266afbf8e00b28705ab4b41d2))
    - Define dependencies on the workspace level ([`96fa08b`](https://github.com/aya-rs/aya/commit/96fa08bd82233268154edf30b106876f5a4f0e30))
    - Merge pull request #650 from aya-rs/test-cleanup ([`61608e6`](https://github.com/aya-rs/aya/commit/61608e64583f9dc599eef9b8db098f38a765b285))
    - Include ~all crates in default members ([`6d06e2b`](https://github.com/aya-rs/aya/commit/6d06e2bf3a6d267589339743fef694763b5cc5af))
    - Merge pull request #640 from aya-rs/lossy-conversions ([`ed70a47`](https://github.com/aya-rs/aya/commit/ed70a478454bae41a0c1ba3523baffb4e24f41a2))
    - Suppress resolver warning on nightly ([`e08c647`](https://github.com/aya-rs/aya/commit/e08c6471dd351a1b717a38301a0ded5f04d1450d))
    - Unify IP format hints into one, repsesent it by `:i` token ([`84e5e28`](https://github.com/aya-rs/aya/commit/84e5e2894f226f4b2c7cb637a6f44d5773b927e6))
    - Merge pull request #456 from dmitris/uninlined_format_args ([`16b029e`](https://github.com/aya-rs/aya/commit/16b029ed3708470afd2a6d67615b30c8d30b5059))
    - Fix uninlined_format_args clippy issues ([`055d94f`](https://github.com/aya-rs/aya/commit/055d94f58be4f80ada416b99278a22f600c71285))
    - Merge pull request #436 from vadorovsky/aya-log-mac-addr ([`3adb9b0`](https://github.com/aya-rs/aya/commit/3adb9b049f493ec9b80fcf868a8eac3363d17844))
    - Add format hints for MAC addresses ([`2223ab8`](https://github.com/aya-rs/aya/commit/2223ab828d6db40a85cff4737f6164ed8ee9e42d))
    - Add display hints ([`83ec27f`](https://github.com/aya-rs/aya/commit/83ec27f06b6859f455f2b2baf985b8fd3fb4adc5))
</details>

