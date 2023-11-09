# Aya Integration Tests

The Aya integration test suite is a set of tests to ensure that
common usage behaviours work on real Linux distros

## Prerequisites

You'll need:

1. `rustup toolchain install nightly`
1. `rustup target add {aarch64,x86_64}-unknown-linux-musl`
1. `cargo install bpf-linker`
1. (virtualized only) `qemu`

## Usage

From the root of this repository:

### Native

```console
cargo xtask integration-test local
```

### Virtualized

VM tests require a kernel image to test with.

#### Obtaining a kernel image

##### Debian

To download an image from the Debian project:

- Browse to the [Debian FTP site](ftp://ftp.us.debian.org/debian/pool/main/l/linux/) for the kernel version you require
- Download the kernel into `tests/.tmp/debian-kernels/${architecture}/`

```bash
wget -nd -q -P test/.tmp/debian-kernels/x86_64 \
  ftp://ftp.us.debian.org/debian/pool/main/l/linux/linux-image-5.10.0-23-cloud-amd64-unsigned_5.10.179-3_amd64.deb
```

- Extract the kernel image:

```bash
dpkg --fsys-tarfile test/.tmp/debian-kernels/arm64/linux-image-5.10.0-23-cloud-amd64-unsigned_5.10.179-3_amd64.deb | tar -C test/.tmp --wildcards --extract '*vmlinuz*' --file -
```

#### Fedora

To download an image from the Fedora project:

- Search for the kernel version you require on [Koji](https://koji.fedoraproject.org/koji/search?match=glob&type=build&terms=kernel-4*)
- Copy the download link for the `kernel-core-${version}.rpm` and download it into `tests/.tmp/fedora-kernels/${architecture}/`

```bash
wget -nd -P test/.tmp/fedora-kernels/x86_64 \
  https://kojipkgs.fedoraproject.org//packages/kernel/5.10.23/200.fc33/x86_64/kernel-core-5.10.23-200.fc33.x86_64.rpm
```

- Extract the kernel image:

```bash
rpm2cpio ./test/.tmp/fedora-kernels/x86_64/kernel-core-5.10.23-200.fc33.x86_64.rpm \
  | cpio -iv --to-stdout ./lib/modules/5.10.23-200.fc33.x86_64/vmlinuz > ./test/.tmp/boot/vmlinuz-5.10.23-200.fc33.x86_64
```

#### Running the tests

To run the tests run the following command, replacing `/path/to/vmlinuz` with
the path to the kernel image you extracted above:

```console
cargo xtask integration-test vm /path/to/vmlinuz
```

### Writing an integration test

Tests should follow these guidelines:

- Rust eBPF code should live in `integration-ebpf/${NAME}.rs` and be included in
  `integration-ebpf/Cargo.toml` and `integration-test/src/lib.rs` using
  `include_bytes_aligned!`.
- C eBPF code should live in `integration-test/bpf/${NAME}.bpf.c`. It should be
  added to the list of files in `integration-test/build.rs` and the list of
  constants in `integration-test/src/lib.rs` using `include_bytes_aligned!`.
- Tests should be added to `integration-test/tests`.
- You may add a new module, or use an existing one.
- Test functions should not return `anyhow::Result<()>` since this produces errors without stack
  traces. Prefer to `panic!` instead.
