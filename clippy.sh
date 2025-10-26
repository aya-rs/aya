#!/usr/bin/env sh

set -eux

# `-C panic=abort` because "unwinding panics are not supported without std"; integration-ebpf
# contains `#[no_std]` binaries.
# 
# `-Zpanic_abort_tests` because "building tests with panic=abort is not supported without
# `-Zpanic_abort_tests`"; Cargo does this automatically when panic=abort is set via profile but we
# want to preserve unwinding at runtime - here we are just running clippy so we don't care about
# unwinding behavior.
# 
# `+nightly` because "the option `Z` is only accepted on the nightly compiler".
cargo +nightly hack clippy "$@" \
  --all-targets \
  --feature-powerset \
  -- --deny warnings \
  -C panic=abort \
  -Zpanic_abort_tests


for arch in aarch64 arm loongarch64 mips powerpc64 riscv64 s390x x86_64; do
  for target in bpfeb-unknown-none bpfel-unknown-none; do
    RUSTFLAGS="--cfg bpf_target_arch=\"$arch\"" cargo +nightly hack clippy \
      --target "$target" \
      -Zbuild-std=core \
      --package aya-ebpf-bindings \
      --package aya-ebpf \
      --package aya-log-ebpf \
      --package integration-ebpf \
      --feature-powerset \
      -- --deny warnings
    done
done
