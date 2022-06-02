#!/bin/sh
# SUMMARY: Check that the program can be unloaded
# LABELS:

set -ex

# Source libraries. Uncomment if needed/defined
#. "${RT_LIB}"
. "${RT_PROJECT_ROOT}/_lib/lib.sh"

NAME=test

clean_up() {
    rm -rf ebpf user ${NAME}.o ${NAME}
    exec_vm rm ${NAME} ${NAME}.o
}

trap clean_up EXIT

# Test code goes here
compile_ebpf ${NAME}.ebpf.rs
compile_user ${NAME}.rs

scp_vm ${NAME}.o
scp_vm ${NAME}

exec_vm sudo ./${NAME}