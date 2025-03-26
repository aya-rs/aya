#!/usr/bin/env sh

set -eux

cargo hack clippy "$@" --all-targets --feature-powerset --workspace -- --deny warnings
