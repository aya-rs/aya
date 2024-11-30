#!/usr/bin/env sh

set -eux

# We cannot run clippy over the whole workspace at once due to feature unification. Since both
# integration-test and integration-ebpf depend on integration-common and integration-test activates
# integration-common's aya dependency, we end up trying to compile the panic handler twice: once
# from the bpf program, and again from std via aya.
# 
# `-C panic=abort` because "unwinding panics are not supported without std"; integration-ebpf
# contains `#[no_std]` binaries.
# 
# `-Zpanic_abort_tests` because "building tests with panic=abort is not supported without
# `-Zpanic_abort_tests`"; Cargo does this automatically when panic=abort is set via profile but we
# want to preserve unwinding at runtime - here we are just running clippy so we don't care about
# unwinding behavior.
# 
# `+nightly` because "the option `Z` is only accepted on the nightly compiler".
cargo +nightly hack clippy "$@" --exclude integration-ebpf --all-targets --feature-powerset --workspace -- --deny warnings
cargo +nightly hack clippy "$@" --package integration-ebpf --all-targets --feature-powerset -- --deny warnings -C panic=abort -Zpanic_abort_tests
