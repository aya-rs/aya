#!/bin/sh
# SUMMARY: Check that a program with multiple maps in the maps section loads
# LABELS:

set -e

# Source libraries. Uncomment if needed/defined
#. "${RT_LIB}"
. "${RT_PROJECT_ROOT}/_lib/lib.sh"

NAME=multimap

clean_up() {
    rm -rf ${NAME}.o ${NAME}
    exec_vm rm -f ${NAME}.o ${NAME}
}

trap clean_up EXIT

# Test code goes here
compile_c_ebpf "$(pwd)/${NAME}.bpf.c"
compile_user "$(pwd)/${NAME}.rs"

scp_vm ${NAME}.o
scp_vm ${NAME}

exec_vm sudo ./${NAME}

exit 0