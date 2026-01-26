#!/usr/bin/env sh

set -eux

# macOS cross-compilation fixes for libbpf-sys vendored dependencies.
#
# PATH and CFLAGS are set here (not in libbpf-sys.env) because they need
# absolute paths. In CI, they also use separate mechanisms (GITHUB_PATH vs
# GITHUB_ENV).
#
# See https://github.com/libbpf/libbpf-sys/issues/137.
if [ "$(uname -s)" = "Darwin" ]; then
  script_dir=$(cd "$(dirname "$0")" && pwd)
  export PATH="$script_dir/ci/bin:$PATH"
  export CFLAGS="-I$script_dir/ci/headers"
  set -a
  . "$script_dir/ci/libbpf-sys.env"
  . "$script_dir/ci/macos-toolchain.env"
  set +a
fi

# `-C panic=abort` because "unwinding panics are not supported without std"; integration-ebpf
# contains `#[no_std]` binaries.
#
# `-Zpanic_abort_tests` because "building tests with panic=abort is not supported without
# `-Zpanic_abort_tests`"; Cargo does this automatically when panic=abort is set via profile but we
# want to preserve unwinding at runtime - here we are just running clippy so we don't care about
# unwinding behavior.
#
# `+nightly` because "the option `Z` is only accepted on the nightly compiler".
#
# On macOS, target Linux since aya uses Linux-specific libc constants.
if [ "$(uname -s)" = "Darwin" ]; then
  target_args="--target x86_64-unknown-linux-musl"
else
  target_args=""
fi

cargo +nightly hack clippy "$@" \
  $target_args \
  --all-targets \
  --feature-powerset \
  -- --deny warnings \
  -C panic=abort \
  -Zpanic_abort_tests

export CLIPPY_ARGS='--deny=warnings'
export RUSTDOCFLAGS='--no-run -Z unstable-options --test-builder clippy-driver'

cargo +nightly hack test --doc "$@" $target_args --feature-powerset

for arch in aarch64 arm loongarch64 mips powerpc64 riscv64 s390x x86_64; do
  export RUSTFLAGS="--cfg bpf_target_arch=\"$arch\""

  for target in bpfeb-unknown-none bpfel-unknown-none; do
    cargo +nightly hack clippy \
      --target "$target" \
      -Zbuild-std=core \
      --package aya-ebpf \
      --package aya-ebpf-bindings \
      --package aya-log-ebpf \
      --package integration-ebpf \
      --feature-powerset \
      -- --deny warnings
  done

  RUSTDOCFLAGS="$RUSTDOCFLAGS $RUSTFLAGS" cargo +nightly hack test --doc "$@" \
    --package aya-ebpf \
    --package aya-ebpf-bindings \
    --package aya-log-ebpf \
    --package integration-ebpf \
    --feature-powerset
done
