#!/bin/sh
# SUMMARY: Check that long names are properly truncated
# LABELS:

set -e

# Source libraries. Uncomment if needed/defined
#. "${RT_LIB}"
. "${RT_PROJECT_ROOT}/_lib/lib.sh"

NAME=name_test

clean_up() {
    rm -rf ebpf user ${NAME}.o ${NAME}
    exec_vm sudo pkill -9 ${NAME}
    exec_vm rm ${NAME} ${NAME}.o
}

trap clean_up EXIT

# Test code goes here
compile_ebpf ${NAME}.ebpf.rs
compile_user ${NAME}.rs

scp_vm ${NAME}.o
scp_vm ${NAME}

exec_vm sudo ./${NAME}&
prog_list=$(exec_vm sudo bpftool prog)
echo "${prog_list}" | grep -q "xdp  name ihaveaverylongn  tag"

exit 0