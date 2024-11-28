#!/usr/bin/env sh

# `-C panic=abort` because "unwinding panics are not supported without std";
# integration-ebpf contains `#[no_std]` binaries.
#
# `-Zpanic_abort_tests` because "building tests with panic=abort is not supported without
# `-Zpanic_abort_tests`"; Cargo does this automatically when panic=abort is set via profile
# but we want to preserve unwinding at runtime - here we are just running clippy so we don't
# care about unwinding behavior.
#
# `+nightly` because "the option `Z` is only accepted on the nightly compiler".
exec cargo +nightly hack clippy "$@" --all-targets --feature-powerset --workspace -- --deny warnings -C panic=abort -Zpanic_abort_tests
