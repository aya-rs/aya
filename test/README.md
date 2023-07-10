Aya Integration Tests
=====================

The aya integration test suite is a set of tests to ensure that
common usage behaviours work on real Linux distros
## Prerequisites

### Linux

To run locally all you need is:

1. Rust nightly
2. `libelf`
3. A checkout of [libbpf](https://github.com/libbpf/libbpf)
4. `cargo install bpf-linker`
5. `bpftool`

### Other OSs

1. A POSIX shell
1. A checkout of [libbpf](https://github.com/libbpf/libbpf)
1. `rustup target add x86_64-unknown-linux-musl`
1. `cargo install bpf-linker`
1. Install `qemu` and `cloud-init-utils` package - or any package that provides `cloud-localds`

## Usage

From the root of this repository:

### Native

```
cargo xtask integration-test
```

### Virtualized

```
./test/run.sh ./libbpf
```

### Writing an integration test

Tests should follow these guidelines:

- Rust eBPF code should live in `integration-ebpf/${NAME}.rs` and included in
  `integration-ebpf/Cargo.toml`.
- C eBPF code should live in `integration-test/bpf/${NAME}.bpf.c`. It should be
  added to the list of files in `integration-test/build.rs` and the list of
  constants in `integration-test/src/lib.rs` using `include_bytes_aligned!`.
- Tests should be added to `integration-test/tests`.
- You may add a new module, or use an existing one.
- Test functions should not return `anyhow::Result<()>` since this produces errors without stack
  traces. Prefer to `panic!` instead.
