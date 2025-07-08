# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Aya is a pure-Rust eBPF library built without dependencies on libbpf or bcc. It provides a complete eBPF development stack with both userspace and kernel-space components, supporting BTF (BPF Type Format) for portable "compile once, run everywhere" eBPF programs.

## Key Components

### Crate Structure
- **aya**: Main userspace library for loading and managing eBPF programs
- **aya-obj**: BPF object file parsing and manipulation
- **aya-build**: Build-time utilities for eBPF program compilation
- **aya-log**: Logging infrastructure for eBPF programs
- **aya-tool**: Command-line tools for eBPF development
- **aya-ebpf**: Kernel-space eBPF program development library (no_std)
- **aya-ebpf-bindings**: Low-level kernel bindings for eBPF programs
- **test-distro**: Testing infrastructure for different kernel versions

### Program Types
The library supports all major eBPF program types:
- **Probes**: KProbe, UProbe, TracePoint, RawTracePoint, BtfTracePoint
- **Network**: XDP, TC (traffic control), SocketFilter, SkMsg, SkSkb, SockOps
- **Cgroup**: CgroupSkb, CgroupSock, CgroupSockAddr, CgroupSockopt, CgroupSysctl, CgroupDevice
- **Security**: LSM (Linux Security Module), FEntry, FExit
- **Specialized**: PerfEvent, LircMode2, FlowDissector, SkLookup, Extension, Iter

### Map Types
Comprehensive map support including:
- Basic: Array, HashMap, LruHashMap, PerCpuArray, PerCpuHashMap
- Advanced: RingBuf, PerfEventArray, BloomFilter, LpmTrie, Stack, Queue
- Specialized: SockMap, SockHash, CpuMap, DevMap, XskMap, ProgramArray

## Common Development Commands

### Building
```bash
# Build all workspace members
cargo build

# Build specific crate
cargo build -p aya
```

### Testing
```bash
# Run unit tests
cargo test

# Run integration tests (requires special setup)
cargo xtask integration-test local

# Run virtualized integration tests
cargo xtask integration-test vm
```

### Linting and Formatting
```bash
# Format code
cargo +nightly fmt --all

# Run clippy with project-specific configuration
./clippy.sh

# Run clippy with arguments
./clippy.sh --fix
```

### eBPF-specific Commands
```bash
# Generate code from kernel headers
cargo xtask codegen

# Check public API compatibility
cargo xtask public-api

# Build documentation
cargo xtask docs
```

### Architecture-specific Building
```bash
# Build eBPF programs for specific target
cargo +nightly build --target bpfel-unknown-none -Z build-std=core

# Build for specific BPF architecture
CARGO_CFG_BPF_TARGET_ARCH=x86_64 cargo +nightly build --target bpfel-unknown-none
```

## Key Architecture Patterns

### EbpfLoader Pattern
The main loading mechanism uses a builder pattern:
```rust
let mut bpf = EbpfLoader::new()
    .btf(Btf::from_sys_fs().ok().as_ref())
    .map_pin_path("/sys/fs/bpf/my-program")
    .set_global("CONFIG_VALUE", &42u32, true)
    .load_file("program.o")?;
```

### Program Lifecycle
1. Parse object file with `Object::parse()`
2. Apply relocations (BTF, maps, calls)
3. Load into kernel with appropriate program type
4. Attach to hook points

### Map Management
- Maps are created during object loading
- Support for pinning in `/sys/fs/bpf/`
- Automatic BTF integration when available
- Per-CPU variants for performance

## Development Notes

### Feature Detection
The library automatically detects kernel BPF features at runtime through `detect_features()` and stores them in a global `FEATURES` static.

### Cross-compilation
- Uses `bpf-linker` for linking eBPF programs
- Requires nightly Rust for eBPF target compilation
- Supports multiple architectures: x86_64, aarch64, arm, riscv64, powerpc64, s390x, mips

### Testing Infrastructure
- `test-distro` provides a minimal Linux distribution for testing
- Integration tests run against multiple kernel versions
- Virtualized testing with QEMU for different architectures

### Workspace Configuration
- Uses Rust 2024 edition
- Minimum supported Rust version: 1.85.0
- Shared dependencies managed through `workspace.dependencies`
- Default members exclude integration tests (built separately)

## Important File Locations

- **Build configuration**: `Cargo.toml` (workspace root)
- **CI configuration**: `.github/workflows/ci.yml`
- **Rust toolchain**: `ebpf/rust-toolchain.toml`
- **Format configuration**: `rustfmt.toml`
- **eBPF programs**: `ebpf/` directory
- **Integration tests**: `test/integration-test/` and `test/integration-ebpf/`
- **Test kernels**: `test/.tmp/` (downloaded during CI)