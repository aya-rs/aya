# Development Environment

## Prerequisites

Before getting started you will need the Rust stable and nightly tool-chains installed on your system.
This is easily achieved with [`rustup`]:

```console
rustup install stable
rustup install nightly --component rust-src
```

Once you have the Rust tool-chains installed, you must also install the `bpf-linker` - for linking our eBPF program - and `cargo-generate` - for generating the project skeleton.

```console
cargo +nightly install bpf-linker
cargo install --git https://github.com/cargo-generate/cargo-generate
```

## Starting A New Project

To start a new project, you can use `cargo-generate`:

```console
cargo generate https://github.com/dave-tucker/aya-template
```

This will prompt you for a project name. We'll be using `myapp` in this example