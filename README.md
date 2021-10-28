# Aya

[![Crates.io][crates-badge]][crates-url]
![License][license-badge]
![Build status][build-badge]
[![Documentaiton][docs-badge]][docs-url]

[crates-badge]: https://img.shields.io/crates/v/aya.svg
[crates-url]: https://crates.io/crates/aya
[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue
[build-badge]: https://github.com/aya-rs/aya/actions/workflows/build-aya.yml/badge.svg
[docs-badge]: https://img.shields.io/badge/docs-website-blue.svg
[docs-url]: http://aya-rs.github.io/book/

[API docs][api-docs] | [Chat][chat-url] | [Aya-Related Projects][awesome-aya]

[api-docs]: https://docs.rs/aya
[chat-url]: https://discord.gg/xHW2cb2N6G
[awesome-aya]: https://github.com/aya-rs/awesome-aya

## Overview

eBPF is a technology that allows running user-supplied programs inside the Linux
kernel. For more info see https://ebpf.io/what-is-ebpf.

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

Aya supports a large chunk of the eBPF API. The following example shows how to use a
`BPF_PROG_TYPE_CGROUP_SKB` program with aya:


```rust
use std::fs::File;
use std::convert::TryInto;
use aya::Bpf;
use aya::programs::{CgroupSkb, CgroupSkbAttachType};

// load the BPF code
let mut bpf = Bpf::load_file("bpf.o")?;

// get the `ingress_filter` program compiled into `bpf.o`.
let ingress: &mut CgroupSkb = bpf.program_mut("ingress_filter")?.try_into()?;

// load the program into the kernel
ingress.load()?;

// attach th program to the root cgroup. `ingress_filter` will be called for all
// incoming packets.
let cgroup = File::open("/sys/fs/cgroup/unified")?;
ingress.attach(cgroup, CgroupSkbAttachType::Ingress)?;
```

## Community

Join [the conversation on Discord][chat-url] to discuss anything related to aya.

## Contributing

Please see the [contributing guide](https://github.com/aya-rs/aya/blob/main/CONTRIBUTING.md).
## License

Aya is distributed under the terms of either the [MIT license] or the [Apache License] (version
2.0), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[MIT license]: https://github.com/aya-rs/aya/blob/main/LICENSE-MIT
[Apache license]: https://github.com/aya-rs/aya/blob/main/LICENSE-APACHE
