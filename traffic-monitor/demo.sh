#!/bin/bash
echo "🚀 Traffic Monitor Demo - Linux Container Environment"
echo "===================================================="
echo

echo "📊 System Information:"
echo "  Kernel: $(uname -r)"
echo "  Architecture: $(uname -m)" 
echo "  OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
echo "  Container: $([ -f /.dockerenv ] && echo "Docker" || echo "Unknown")"
echo

echo "🔧 Available Network Interfaces:"
ip link show | grep -E "^[0-9]+:" | while read line; do
  iface=$(echo "$line" | cut -d: -f2 | tr -d " ")
  state=$(echo "$line" | grep -o "state [A-Z]*" | cut -d" " -f2 || echo "UNKNOWN")
  echo "  $iface ($state)"
done
echo

echo "📦 Development Tools:"
echo "  Rust: $(rustc --version)"
echo "  Cargo: $(cargo --version)"
echo

echo "🧪 Running Traffic Monitor Tests:"
echo "=================================="
cargo test --release --lib
echo

echo "📋 Configuration Example:"
echo "========================"
if [ -f configs/default.json ]; then
    echo "Default permitted networks:"
    cat configs/default.json | jq .
else
    echo '{"permitted_cidrs":["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"]}' | jq .
fi
echo

echo "🎯 Running Standalone Demo:"
echo "==========================="
cargo run --example standalone-demo --release
echo

echo "🐧 Linux eBPF Capability Check:"
echo "==============================="
echo "Kernel version: $(uname -r)"
if [ -d /sys/kernel/btf ]; then
    echo "✅ BTF support: Available"
else
    echo "❌ BTF support: Not available"
fi

if [ -f /proc/kallsyms ]; then
    if grep -q bpf /proc/kallsyms 2>/dev/null; then
        echo "✅ BPF syscalls: Available"
    else
        echo "❌ BPF syscalls: Limited visibility"
    fi
else
    echo "❌ Kernel symbols: Not accessible"
fi

echo
echo "📈 What the Full Traffic Monitor Would Do:"
echo "=========================================="
echo "1. Load eBPF program into kernel at XDP layer"
echo "2. Attach to network interface (e.g., eth0)"
echo "3. Process packets at line speed in kernel space"
echo "4. Filter based on source IP against CIDR ranges"
echo "5. Log non-permitted traffic via ring buffer"
echo "6. Optionally drop packets in kernel (--drop-packets)"
echo "7. Provide real-time statistics in userspace"
echo

echo "🔧 To run the actual traffic monitor (requires privileges):"
echo "sudo ./target/release/traffic-monitor -i eth0 -c configs/default.json"
echo

echo "✅ Demo completed successfully!"