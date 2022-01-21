#!/bin/sh
# SUMMARY: Check that a simple XDP program an be loaded
# LABELS:

set -e

# Source libraries. Uncomment if needed/defined
#. "${RT_LIB}"
. "${RT_PROJECT_ROOT}/_lib/lib.sh"

NAME=pass

clean_up() {
    rm -rf ${NAME}.o ${NAME}
    exec_vm rm -f ${NAME} ${NAME}.o
}

trap clean_up EXIT

# Test code goes here
compile_ebpf "$(pwd)/${NAME}.ebpf.rs"
compile_user "$(pwd)/${NAME}.rs"

scp_vm ${NAME}.o
scp_vm ${NAME}

exec_vm sudo ./${NAME}

exit 0