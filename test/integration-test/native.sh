#!/usr/bin/env bash
set -euo pipefail

test_binary="${TEST_SRCDIR:?}/${TEST_WORKSPACE:?}/$1"
shift

export RUST_BACKTRACE=1 RUST_LOG=debug
exec sudo -E "$test_binary" --test-threads=1 "$@"
