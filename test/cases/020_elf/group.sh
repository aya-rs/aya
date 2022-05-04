#!/bin/sh
# SUMMARY: Tests to check ELF from aya-bpf
# LABELS:

# Source libraries. Uncomment if needed/defined
# . "${RT_LIB}"
. "${RT_PROJECT_ROOT}/_lib/lib.sh"

set -e

group_init() {
    # Group initialisation code goes here
    return 0
}

group_deinit() {
    # Group de-initialisation code goes here
    return 0
}

CMD=$1
case $CMD in
init)
    group_init
    res=$?
    ;;
deinit)
    group_deinit
    res=$?
    ;;
*)
    res=1
    ;;
esac

exit $res