Aya Regression Tests
====================

The aya regression test suite is a set of tests to ensure that
common usage behaviours work on real Linux distros
## Prerequisites

This assumes you have a working Rust and Go toolchain on the host machine

1. `rustup target add x86_64-unknown-linux-musl`
1. Install [`rtf`](https://github.com/linuxkit/rtf): `go install github.com/linuxkit/rtf@latest`
1. Install rust-script: `cargo install rust-script`
1. Install `qemu` and `cloud-init-utils` package - or any package that provides `cloud-localds`

It is not required, but the tests run significantly faster if you use `sccache`

You may also use the docker image to run the tests:

```
docker run -it --rm --device /dev/kvm -v/home/dave/dev/aya-rs/aya:/src -w /src/test ghcr.io/aya-rs/aya-test-rtf:main
```

## Usage

To read more about how to use `rtf`, see the [documentation](https://github.com/linuxkit/rtf/blob/master/docs/USER_GUIDE.md)

### Run the tests with verbose output

```
rtf -vvv run
```
### Run the tests using an older kernel

```
AYA_TEST_IMAGE=centos8 rtf -vvv run
```

### Writing a test

Tests should follow this pattern:

- The eBPF code should be in a file named `${NAME}.ebpf.rs`
- The userspace code should be in a file named `${NAME}.rs`
- The userspace program should make assertions and exit with a non-zero return code to signal failure
- VM start and stop is handled by the framework
- Any files copied to the VM should be cleaned up afterwards

See `./cases` for examples