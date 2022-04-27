#!/bin/sh
# SUMMARY: Check that maps are correctly represented in ELF files
# LABELS:

set -ex

# Source libraries. Uncomment if needed/defined
#. "${RT_LIB}"
. "${RT_PROJECT_ROOT}/_lib/lib.sh"

NAME=map_test

clean_up() {
    rm -rf ebpf user ${NAME}.o
}

trap clean_up EXIT

# Test code goes here
compile_ebpf ${NAME}.ebpf.rs

readelf --sections ${NAME}.o | grep -q "maps"
readelf --syms ${NAME}.o | grep -q "BAR"

exit 0