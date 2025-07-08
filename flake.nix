{
  description = "Aya eBPF development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Rust toolchain with stable for general development
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "clippy" "rustfmt" ];
        };

        # Nightly Rust for eBPF compilation (when on Linux)
        rustNightly = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [ "rust-src" ];
        };

      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust toolchains
            rustToolchain
            rustNightly

            # Development tools
            cargo-watch
            cargo-edit
            cargo-audit
            cargo-deny
            cargo-expand
            
            # System tools
            git
            curl
            wget
            
            # JSON processing
            jq
            
            # Documentation
            mdbook
            
            # Testing and CI tools
            taplo-cli  # TOML formatter
            
            # Additional useful tools
            fd
            ripgrep
            bat
            eza
            
            # Optional eBPF tools (available on some platforms)
            pkg-config
            
          ] ++ lib.optionals stdenv.isLinux [
            # Linux-specific eBPF tools
            llvm_15
            clang_15
            libbpf
            bpftools
            iproute2
            nettools
            tcpdump
            strace
            ltrace
            gdb
          ] ++ lib.optionals stdenv.isDarwin [
            # macOS-specific tools
            darwin.apple_sdk.frameworks.Security
            darwin.apple_sdk.frameworks.CoreFoundation
          ];

          shellHook = ''
            echo "🦀 Aya eBPF Development Environment"
            echo "=================================="
            echo
            echo "Available Rust toolchains:"
            echo "  - Stable: $(rustc --version)"
            echo "  - Nightly: $(rustc +nightly --version 2>/dev/null || echo 'Available for eBPF targets')"
            echo
            echo "Traffic Monitor:"
            echo "  cd traffic-monitor"
            echo "  cargo build --release"
            echo "  cargo run --example macos-demo  # Demo on macOS"
            echo "  cargo test                      # Run tests"
            echo
            echo "System info:"
            echo "  OS: $(uname -s)"
            echo "  Arch: $(uname -m)"
            echo

            # Set up environment variables for development
            export RUST_BACKTRACE="1"
            export RUST_LOG="debug"
            
            # Add cargo tools to PATH if not already there
            export PATH="$HOME/.cargo/bin:$PATH"
            
            # Platform-specific setup
            if [[ "$(uname -s)" == "Linux" ]]; then
              echo "🐧 Running on Linux - eBPF programs can be loaded!"
              if command -v ip >/dev/null 2>&1; then
                echo "   Available interfaces: $(ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' ' | head -5 | tr '\n' ' ')"
              fi
              # Set up for eBPF compilation
              export CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER="bpf-linker"
              export CARGO_TARGET_BPFEB_UNKNOWN_NONE_LINKER="bpf-linker"
              export CARGO_CFG_BPF_TARGET_ARCH="x86_64"
            else
              echo "🍎 Running on $(uname -s) - eBPF demo mode available"
              echo "   For full eBPF testing, use a Linux container or VM"
            fi
            echo
            echo "Ready to start developing! 🚀"
            echo
          '';
        };

        # Minimal shell for quick access
        devShells.minimal = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            pkg-config
            git
            jq
          ];
          shellHook = ''
            echo "🦀 Minimal Rust environment for Aya"
          '';
        };
      }
    );
}