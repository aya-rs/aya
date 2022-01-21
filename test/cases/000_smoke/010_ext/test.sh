#!/bin/sh
# SUMMARY: Check that a simple XDP program an be loaded
# LABELS:

set -e

# Source libraries. Uncomment if needed/defined
#. "${RT_LIB}"
. "${RT_PROJECT_ROOT}/_lib/lib.sh"

NAME=ext

clean_up() {
    rm -rf main.o ${NAME}.o ${NAME}
    exec_vm rm -f main.o ${NAME}.o ${NAME}
}

trap clean_up EXIT

# Test code goes here
compile_c_ebpf "$(pwd)/main.bpf.c"
compile_c_ebpf "$(pwd)/${NAME}.bpf.c"
compile_user "$(pwd)/${NAME}.rs"

scp_vm main.o
scp_vm ${NAME}.o
scp_vm ${NAME}

exec_vm sudo ./${NAME}

exit 0