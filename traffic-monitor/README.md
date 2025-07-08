# Traffic Monitor

A high-performance eBPF-based network traffic monitoring tool built with Aya. This tool monitors incoming traffic at the XDP (eXpress Data Path) layer and logs traffic from IP addresses that are not in a configured permitted list.

## Features

- **XDP-based monitoring**: High-performance packet processing at the network driver level
- **CIDR range support**: Configure permitted IP ranges using CIDR notation
- **Protocol detection**: Identifies and logs TCP, UDP, ICMP, and other IP protocols  
- **Flexible actions**: Option to log-only or log-and-drop non-permitted traffic
- **Real-time statistics**: Periodic summaries of traffic patterns
- **JSON configuration**: Easy-to-manage configuration files
- **Structured logging**: Multiple output formats (JSON, CSV, JSONL, Console) for analytics
- **Log analysis**: Built-in analysis script with threat detection and traffic insights

## Architecture

The tool consists of two main components:

1. **eBPF Program** (`traffic_monitor.bpf.rs`): Runs in kernel space at the XDP layer
   - Parses Ethernet and IP headers
   - Checks source IPs against permitted CIDR ranges
   - Logs non-permitted traffic via ring buffer
   - Optionally drops packets based on configuration

2. **Userspace Program** (`main.rs`): Manages the eBPF program and processes events
   - Loads and configures the eBPF program
   - Processes events from the ring buffer
   - Provides statistics and logging
   - Handles configuration management

## Installation

From the aya repository root:

```bash
cd traffic-monitor
cargo build --release
```

## Usage

### Basic Usage

```bash
# Monitor interface eth0 with default configuration (log only)
sudo ./target/release/traffic-monitor --interface eth0 --config configs/default.json

# Monitor with packet dropping enabled
sudo ./target/release/traffic-monitor --interface eth0 --config configs/default.json --drop-packets

# Verbose logging
sudo ./target/release/traffic-monitor --interface eth0 --config configs/default.json --verbose
```

### Configuration

Create a JSON configuration file with permitted CIDR ranges:

```json
{
  "permitted_cidrs": [
    "127.0.0.0/8",
    "10.0.0.0/8", 
    "172.16.0.0/12",
    "192.168.0.0/16"
  ]
}
```

Example configurations are provided in the `configs/` directory:
- `default.json`: Standard private networks and localhost
- `strict.json`: Only localhost and a specific /24 network

## Command Line Options

- `--interface, -i`: Network interface to attach to (required)
- `--config, -c`: Path to JSON configuration file (required)
- `--drop-packets`: Drop non-permitted packets instead of just logging
- `--verbose, -v`: Enable verbose logging
- `--log-format`: Log output format (console, json, csv, jsonl)
- `--log-file`: Log output file path (required for non-console formats)
- `--log-buffer-size`: Log buffer size in bytes (default: 8192)

## Examples

### Generate Test Traffic

```bash
# Run the test traffic generator
cargo run --example test-traffic
```

### Monitor Specific Interface

```bash
# Monitor a specific interface
sudo ./target/release/traffic-monitor -i eth0 -c configs/default.json
```

### Strict Monitoring with Packet Dropping

```bash
# Only allow localhost and 192.168.1.0/24, drop everything else
sudo ./target/release/traffic-monitor -i eth0 -c configs/strict.json --drop-packets
```

### Structured Logging Examples

```bash
# Log to JSON file for analysis
sudo ./target/release/traffic-monitor -i eth0 -c configs/default.json \
  --log-format json --log-file traffic.json

# Log to CSV file for spreadsheet analysis
sudo ./target/release/traffic-monitor -i eth0 -c configs/default.json \
  --log-format csv --log-file traffic.csv

# Log to JSONL file (recommended for log analysis)
sudo ./target/release/traffic-monitor -i eth0 -c configs/default.json \
  --log-format jsonl --log-file traffic.jsonl
```

### Log Analysis

```bash
# Analyze traffic logs with automatic format detection
python3 scripts/analyze_logs.py traffic.jsonl

# Analyze CSV logs
python3 scripts/analyze_logs.py traffic.csv --format csv

# Export detailed analysis report
python3 scripts/analyze_logs.py traffic.jsonl --export-report analysis.json
```

## Testing

Run the test suite:

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration_tests

# All tests with verbose output
cargo test -- --nocapture
```

## XDP vs Other eBPF Hook Points

**XDP (chosen for this implementation):**
- ✅ Highest performance (runs before kernel network stack)
- ✅ Efficient packet dropping with minimal CPU overhead
- ✅ Bypasses kernel networking for dropped packets
- ❌ Limited packet modification capabilities
- ❌ No connection tracking context

**TC (Traffic Control):**
- ✅ More packet modification options
- ✅ Access to more kernel network state
- ❌ Lower performance than XDP
- ❌ Runs after some kernel processing

**Socket Filter:**
- ✅ Socket-level visibility
- ✅ Application context
- ❌ Much lower performance
- ❌ Only sees traffic for monitored sockets

## Performance Considerations

- **Ring Buffer Size**: Default 256KB, adjust based on traffic volume
- **Statistics Interval**: Default 60 seconds, can be modified in `event_handler.rs`
- **Maximum CIDR Ranges**: Default 256, can be increased in the eBPF program
- **Memory Usage**: Minimal kernel memory footprint, userspace scales with unique IPs seen

## Troubleshooting

### Permission Issues
```bash
# Ensure you have CAP_SYS_ADMIN or run as root
sudo ./target/release/traffic-monitor ...
```

### XDP Attachment Issues
If XDP attachment fails, try SKB mode (modify `XdpFlags::default()` to `XdpFlags::SKB_MODE` in main.rs):

```rust
program.attach(&opt.interface, XdpFlags::SKB_MODE)?;
```

### Interface Not Found
```bash
# List available interfaces
ip link show
```

### High CPU Usage
- Reduce ring buffer polling frequency
- Increase statistics interval
- Consider using TC hook for lower performance requirements

## Security Considerations

- Runs with elevated privileges (CAP_SYS_ADMIN)
- Packet dropping can cause denial of service
- Log rotation recommended for high-traffic environments
- Monitor for resource exhaustion with many unique source IPs

## Development

### Building eBPF Program

The eBPF program is automatically built via `build.rs` using `aya-build`.

### Adding New Features

1. Modify the eBPF program in `src/traffic_monitor.bpf.rs`
2. Update userspace handling in `src/main.rs` and related modules
3. Add tests in `tests/integration_tests.rs`
4. Update configuration schema if needed

### Debugging

Enable eBPF program logging:
```bash
# View eBPF logs
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## License

This project follows the same license as the Aya project (MIT OR Apache-2.0).