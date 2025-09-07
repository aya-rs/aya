# aya-log - a logging library for eBPF programs

## Overview

`aya-log` is a logging library for eBPF programs written using [aya]. Think of
it as the [log] crate for eBPF.

## Installation

### User space

Add `aya-log` to `Cargo.toml`:

```toml
[dependencies]
aya-log = { git = "https://github.com/aya-rs/aya", branch = "main" }
```

### eBPF side

Add `aya-log-ebpf` to `Cargo.toml`:

```toml
[dependencies]
aya-log-ebpf = { git = "https://github.com/aya-rs/aya", branch = "main" }
```

## Example

Here's an example that uses `aya-log` in conjunction with the [env_logger] crate
to log eBPF messages to the terminal.

### User space code

```rust
use aya_log::EbpfLogger;

env_logger::init();

// Will log using the default logger, which is TermLogger in this case
let logger = EbpfLogger::init(&mut bpf).unwrap();
let mut logger = tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE).unwrap();
tokio::task::spawn(async move { 
    loop {
        let mut guard = logger.readable_mut().await.unwrap();
        guard.get_inner_mut().flush();
        guard.clear_ready();
    }
});
```

### eBPF code

```rust
use aya_log_ebpf::info;

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    if let Some(port) = tcp_dest_port(&ctx)? {
        if block_port(port) {
            info!(&ctx, "❌ blocked incoming connection on port: {}", port);
            return Ok(XDP_DROP);
        }
    }

    Ok(XDP_PASS)
}
```

[aya]: https://github.com/aya-rs/aya
[log]: https://docs.rs/log
[env_logger]: https://docs.rs/env_logger

## Disabling log levels at load-time

eBPF instruction budgets are tight. Even if a log statement never executes at
runtime, the verifier must still evaluate its instructions unless it can prove
they're unreachable. `aya-log` now exposes a global `AYA_LOG_LEVEL` inside the
eBPF object allowing you to selectively enable levels before the program is
loaded.

By default all bits are set (all logging enabled). To disable all logging:

```rust
let mut bpf = aya::EbpfLoader::new()
    .set_global(aya_log::LEVEL, &0, false /* must_exist */)
    .load_file("prog.bpf.o")?;
# Ok::<(), aya::EbpfError>(())
```

Enable only Error and Warn:

```rust
let level = aya_log::Level::Warn as u8;
let mut bpf = EbpfLoader::new()
    .set_global(aya_log::LEVEL, &level, false /* must_exist */)
    .load_file("prog.bpf.o")?;
```

Because the level is placed in global read-only data, the verifier sees the
disabled branch as unreachable and prunes the logging instructions, reducing
overall instruction count and avoiding potential instruction limit issues.
