#!/usr/bin/env sh

set -eux

cargo +nightly hack clippy "$@" --all-targets --feature-powerset --workspace -- --deny warnings
