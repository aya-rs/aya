FROM ubuntu:24.04

# Install system dependencies for eBPF development
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libc6-dev \
    clang \
    llvm \
    libelf-dev \
    libssl-dev \
    iproute2 \
    net-tools \
    tcpdump \
    jq \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install nightly Rust for eBPF targets
RUN rustup install nightly
RUN rustup +nightly target add bpfel-unknown-none bpfeb-unknown-none

# Install bpf-linker
RUN cargo install bpf-linker

# Set up working directory
WORKDIR /workspace

# Copy the traffic monitor source
COPY . .

# Build the traffic monitor (this will build the eBPF program too)
RUN cargo build --release

# Create a script to demonstrate the traffic monitor
RUN echo '#!/bin/bash\n\
echo "🚀 Traffic Monitor Demo in Linux Container"\n\
echo "=========================================="\n\
echo\n\
echo "📊 System Information:"\n\
echo "  Kernel: $(uname -r)"\n\
echo "  Architecture: $(uname -m)"\n\
echo "  OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d \\"\\")"\n\
echo\n\
echo "🔧 Available Network Interfaces:"\n\
ip link show | grep -E "^[0-9]+:" | while read line; do\n\
  iface=$(echo "$line" | cut -d: -f2 | tr -d " ")\n\
  state=$(echo "$line" | grep -o "state [A-Z]*" | cut -d" " -f2)\n\
  echo "  $iface ($state)"\n\
done\n\
echo\n\
echo "📦 eBPF Tools Available:"\n\
echo "  clang: $(clang --version | head -1)"\n\
echo "  llvm: $(llvm-config --version)"\n\
echo "  cargo: $(cargo --version)"\n\
echo "  bpf-linker: $(bpf-linker --version || echo \"Available\")"\n\
echo\n\
echo "🧪 Running Unit Tests:"\n\
cargo test --release\n\
echo\n\
echo "📋 Configuration Demo:"\n\
echo "Using default configuration:"\n\
cat configs/default.json | jq .\n\
echo\n\
echo "🏗️  Build Information:"\n\
echo "The traffic monitor has been built with eBPF support."\n\
echo "In a real scenario, you would run:"\n\
echo "  sudo ./target/release/traffic-monitor -i eth0 -c configs/default.json"\n\
echo\n\
echo "⚠️  Note: Running the actual eBPF program requires:"\n\
echo "  1. CAP_SYS_ADMIN capabilities (--privileged flag)"\n\
echo "  2. Access to the host network stack"\n\
echo "  3. Proper network interface"\n\
echo\n\
echo "✅ Traffic Monitor Demo Complete!"\n\
' > /workspace/demo.sh && chmod +x /workspace/demo.sh

CMD ["/workspace/demo.sh"]