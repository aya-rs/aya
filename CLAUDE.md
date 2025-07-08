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

## Traffic Monitor Project

The traffic-monitor directory contains a complete eBPF-based network traffic monitoring solution that demonstrates advanced Aya capabilities. This project was developed as a comprehensive example showcasing XDP (eXpress Data Path) packet processing with structured logging and analytics.

### Development History (Branch: ks/claude-dev)

This project was developed through a comprehensive implementation process that included:

#### Phase 1: Core eBPF Implementation
- **eBPF Kernel Program**: XDP-based packet filtering with CIDR range matching
- **Userspace Management**: Program loading, configuration, and event processing
- **Configuration System**: JSON-based CIDR range management
- **Event Handling**: Real-time statistics and traffic analysis

#### Phase 2: Structured Logging Enhancement
- **Multi-Format Logging**: JSON, CSV, JSONL, and Console output formats
- **Performance Optimization**: Buffered I/O and configurable buffer sizes
- **Flow Correlation**: Unique flow hashing for session tracking
- **Metadata Enrichment**: Timestamps, protocol details, and action logging

#### Phase 3: Analytics and Threat Detection
- **Log Analysis Script**: Comprehensive Python-based analytics tool
- **Threat Detection**: Port scanning, high-volume source, and anomaly detection
- **Statistical Analysis**: Traffic patterns, protocol distribution, and flow analysis
- **Export Capabilities**: JSON and CSV report generation

#### Phase 4: Testing and Documentation
- **Comprehensive Testing**: Unit tests, integration tests, and sample data
- **Docker Integration**: Multiple container configurations for testing
- **Demo Infrastructure**: Standalone demos and validation scripts
- **Documentation**: Complete README with usage examples and architecture

### Key Commits in Development

1. **05b72261**: Project structure initialization with Cargo configuration
2. **b5bedb4f**: Core eBPF functionality with XDP packet processing
3. **f48e144b**: Structured logging system with multiple output formats
4. **60024872**: Main userspace program with integrated logging
5. **243320b3**: Log analysis script with threat detection
6. **85c09ad9**: Configuration examples and comprehensive test suite
7. **7764e3e0**: Examples and sample data for testing
8. **5de83133**: Comprehensive documentation and README
9. **35abd160**: Docker containerization and demo infrastructure

### Project Structure

```
traffic-monitor/
├── src/
│   ├── main.rs              # Userspace program with CLI
│   ├── traffic_monitor.bpf.rs  # eBPF kernel program
│   ├── logger.rs            # Structured logging system
│   ├── config.rs            # Configuration management
│   ├── event_handler.rs     # Event processing and stats
│   └── ip_utils.rs          # CIDR parsing utilities
├── scripts/
│   └── analyze_logs.py      # Log analysis and threat detection
├── configs/
│   ├── default.json         # Default CIDR ranges
│   ├── strict.json          # Restrictive configuration
│   └── logging-example.json # Logging configuration
├── examples/
│   ├── *.jsonl              # Sample log data
│   ├── *.csv                # CSV format examples
│   └── *.rs                 # Demo programs
├── tests/
│   └── integration_tests.rs # Comprehensive test suite
└── Dockerfile*              # Container configurations
```

### Build and Test Commands

```bash
# Build the traffic monitor
cd traffic-monitor
cargo build --release

# Run tests
cargo test

# Run with sample data analysis
python3 scripts/analyze_logs.py examples/comprehensive_traffic.jsonl

# Docker demo (Linux container)
docker build -f Dockerfile.simple -t traffic-monitor .
docker run --rm traffic-monitor

# Usage examples
sudo ./target/release/traffic-monitor -i eth0 -c configs/default.json
sudo ./target/release/traffic-monitor -i eth0 -c configs/default.json \
  --log-format jsonl --log-file traffic.jsonl
```

### Key Features Implemented

- **High-Performance Monitoring**: XDP-based packet processing at line rate
- **Flexible Configuration**: JSON-based CIDR range management
- **Structured Logging**: Multiple output formats for analytics integration
- **Threat Detection**: Automated security analysis and anomaly detection
- **Cross-Platform Testing**: Docker containerization for Linux environments
- **Comprehensive Documentation**: Usage examples and troubleshooting guides