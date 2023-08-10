# [![Aya](assets/logo.svg)](https://aya-rs.dev)

[![Crates.io][crates-badge]][crates-url]
![License][license-badge]
[![Build status][build-badge]][build-url]
[![Book][book-badge]][book-url]

[crates-badge]: https://img.shields.io/crates/v/aya.svg?style=for-the-badge&logo=rust
[crates-url]: https://crates.io/crates/aya
[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue?style=for-the-badge
[build-badge]: https://img.shields.io/github/actions/workflow/status/aya-rs/aya/ci.yml?style=for-the-badge
[build-url]: https://github.com/aya-rs/aya/actions/workflows/ci.yml
[book-badge]: https://img.shields.io/badge/read%20the-book-9cf.svg?style=for-the-badge&logo=mdbook
[book-url]: https://aya-rs.dev/book

## API Documentation

[![Unreleased Documentation][git-docs-badge]][git-api-docs] [![Documentaiton][api-docs-badge]][api-docs]

[git-docs-badge]: https://img.shields.io/badge/docs-unreleased-red.svg?style=for-the-badge&logo=docsdotrs
[git-api-docs]: https://docs.aya-rs.dev
[api-docs-badge]: https://img.shields.io/badge/docs-released-blue.svg?style=for-the-badge&logo=docsdotrs
[api-docs]: https://docs.rs/aya

## Community

[![Discord][discord-badge]][chat-url] [![Awesome][awesome-badge]][awesome-aya]

Join [the conversation on Discord][chat-url] to discuss anything related to Aya
or discover and contribute to a list of [Awesome Aya][awesome-aya] projects.

[discord-badge]: https://img.shields.io/badge/Discord-chat-5865F2?style=for-the-badge&logo=discord
[chat-url]: https://discord.gg/xHW2cb2N6G
[awesome-aya]: https://github.com/aya-rs/awesome-aya
[awesome-badge]: https://img.shields.io/badge/Awesome-Aya-FC60A8?style=for-the-badge&logo=awesomelists

## Overview

eBPF is a technology that allows running user-supplied programs inside the Linux
kernel. For more info see [What is eBBF](https://ebpf.io/what-is-ebpf).

Aya is an eBPF library built with a focus on operability and developer
experience. It does not rely on [libbpf] nor [bcc] - it's built from the ground
up purely in Rust, using only the [libc] crate to execute syscalls. With BTF
support and when linked with musl, it offers a true [compile once, run
everywhere solution][co-re], where a single self-contained binary can be
deployed on many linux distributions and kernel versions.

Some of the major features provided include:

* Support for the **BPF Type Format** (BTF), which is transparently enabled when
  supported by the target kernel. This allows eBPF programs compiled against
  one kernel version to run on different kernel versions without the need to
  recompile.
* Support for function call relocation and global data maps, which
  allows eBPF programs to make **function calls** and use **global variables
  and initializers**.
* **Async support** with both [tokio] and [async-std].
* Easy to deploy and fast to build: aya doesn't require a kernel build or
  compiled headers, and not even a C toolchain; a release build completes in a matter
  of seconds.

[libbpf]: https://github.com/libbpf/libbpf
[bcc]: https://github.com/iovisor/bcc
[libc]: https://docs.rs/libc
[co-re]: https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html
[tokio]: https://docs.rs/tokio
[async-std]: https://docs.rs/async-std

### Example

Aya supports a large chunk of the eBPF API. The following example shows how to
use a `BPF_PROG_TYPE_CGROUP_SKB` program with aya:

```rust
use std::fs::File;
use aya::Bpf;
use aya::programs::{CgroupSkb, CgroupSkbAttachType};

// load the BPF code
let mut bpf = Bpf::load_file("bpf.o")?;

// get the `ingress_filter` program compiled into `bpf.o`.
let ingress: &mut CgroupSkb = bpf.program_mut("ingress_filter")?.try_into()?;

// load the program into the kernel
ingress.load()?;

// attach the program to the root cgroup. `ingress_filter` will be called for all
// incoming packets.
let cgroup = File::open("/sys/fs/cgroup/unified")?;
ingress.attach(cgroup, CgroupSkbAttachType::Ingress)?;
```

## Contributing

Please see the [contributing guide](https://github.com/aya-rs/aya/blob/main/CONTRIBUTING.md).

## License

Aya is distributed under the terms of either the [MIT license] or the
[Apache License] (version 2.0), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

[MIT license]: https://github.com/aya-rs/aya/blob/main/LICENSE-MIT
[Apache license]: https://github.com/aya-rs/aya/blob/main/LICENSE-APACHE
