#!/bin/sh
# NAME: aya
# SUMMARY: Aya Regression Tests

# Source libraries. Uncomment if needed/defined
# . "${RT_LIB}"
. "${RT_PROJECT_ROOT}/_lib/lib.sh"

group_init() {
    # Group initialisation code goes here
    [ -r "${AYA_TMPDIR}" ] && rm -rf "${AYA_TMPDIR}"
    mkdir "${AYA_TMPDIR}"
    start_vm
}

group_deinit() {
    # Group de-initialisation code goes here
    stop_vm
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
