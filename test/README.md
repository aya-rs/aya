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
cargo xtask integration-test --libbpf-dir /path/to/libbpf
```

### Virtualized


```
./test/run.sh /path/to/libbpf
```
### Writing a test

Tests should follow these guidelines:

- Rust eBPF code should live in `integration-ebpf/${NAME}.rs` and included in `integration-ebpf/Cargo.toml`
- C eBPF code should live in `integration-test/src/bpf/${NAME}.bpf.c`. It's automatically compiled and made available as `${OUT_DIR}/${NAME}.bpf.o`.
- Any bytecode should be included in the integration test binary using `include_bytes_aligned!`
- Tests should be added to `integration-test/src/test`
- You may add a new module, or use an existing one
- Integration tests must use the `#[integration_test]` macro to be included in the build
- Test functions should return `anyhow::Result<()>` since this allows the use of `?` to return errors.
- You may either `panic!` when an assertion fails or `bail!`. The former is preferred since the stack trace will point directly to the failed line.
