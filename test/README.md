# Aya Integration Tests

The aya integration test suite is a set of tests to ensure that
common usage behaviours work on real Linux distros

## Prerequisites

You'll need:

1. `rustup toolchain install nightly`
1. `rustup target add {aarch64,x86_64}-unknown-linux-musl`
1. `cargo install bpf-linker`
1. `libelf-dev` (`libelf-devel` on rpm-based distros)
1. `llvm` (for `llvm-objcopy`)
1. (virtualized only) `qemu`

## Usage

From the root of this repository:

### Native

```bash
cargo xtask integration-test local
```

### Virtualized

```bash
cargo xtask integration-test vm --cache-dir <CACHE_DIR> <KERNEL_ARCHIVES>...
```

### Required feature coverage

Bazel VM test targets can set environment variables for test processes inside
the VM:

```starlark
aya_qemu_vm_test(
    # ... kernel, initramfs, and architecture ...
    guest_env = {"AYA_TEST_REQUIRE_KPROBE_MULTI": "1"},
)
```

The runner passes these as `init.env=NAME=VALUE` boot parameters. The VM's
`/init` applies them to each test process, including overrides of its default
`RUST_LOG` and `RUST_BACKTRACE`. Names must be shell identifiers; values must
not contain ASCII whitespace, double quotes, or NUL. Empty values and additional
`=` characters are supported. Host environment variables are not implicitly
forwarded into the VM.

For local tests, set the same variables in the test process's environment.

`AYA_TEST_REQUIRE_KPROBE_MULTI=1` requires the kprobe helpers and native
multi-kprobe configuration used by the kprobe integration tests. Missing
prerequisites fail instead of skipping. Keep this expectation in the test
target independently of the kernel configuration, so disabling a required
kernel option cannot silently remove coverage. Unset or `0` leaves this
coverage optional; any value other than `0` or `1` fails the test.

### Writing an integration test

Tests should follow these guidelines:

- Rust eBPF code should live in `integration-ebpf/${NAME}.rs` and included in
  `integration-ebpf/Cargo.toml` and `integration-test/src/lib.rs` using
  `include_bytes_aligned!`.
- C eBPF code should live in `integration-test/bpf/${NAME}.bpf.c`. It should be
  added to the list of files in `integration-test/build.rs` and the list of
  constants in `integration-test/src/lib.rs` using `include_bytes_aligned!`.
- Tests should be added to `integration-test/tests`.
- You may add a new module, or use an existing one.
- Test functions should not return `anyhow::Result<()>` since this produces
  errors without stack traces. Prefer to `panic!` instead.
