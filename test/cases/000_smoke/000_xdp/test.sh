#!/bin/sh
# SUMMARY: Check that a simple XDP program an be loaded
# LABELS:

set -e

# Source libraries. Uncomment if needed/defined
#. "${RT_LIB}"
. "${RT_PROJECT_ROOT}/_lib/lib.sh"

NAME=pass

clean_up() {
    rm -rf ebpf user ${NAME}.o ${NAME}
    exec_vm rm -f pass pass.o
}

trap clean_up EXIT

# Test code goes here
compile_ebpf "$(pwd)/${NAME}.ebpf.rs"
compile_user "$(pwd)/${NAME}.rs"

scp_vm pass.o
scp_vm pass

exec_vm sudo ./pass

exit 0