#!/usr/bin/env bash

set -euo pipefail

IMAGES=()
while IFS=  read -r -d ''; do
    IMAGES+=("$REPLY")
done < <(find test/.tmp -name 'vmlinuz-*' -print0)

MODULES=()
for image in ${IMAGES[@]}; do
    image_name=$(basename ${image})
    image_name=${image_name#"vmlinuz-"}
    MODULES+=($(find test/.tmp -type d -ipath "*modules*" -name "${image_name#"vmlinux-"}" | head -n 1))
done

images_len=${#IMAGES[@]}
modules_len=${#MODULES[@]}

if [ "${images_len}" != "${modules_len}" ]; then
    echo "IMAGES=${IMAGES[@]}"
    echo "MODULES=${MODULES[@]}"
    echo "ERROR! len images != len modules"
    exit 1
fi

args=""
for (( i=0; i<${images_len}; i++ )); do
  args+="-i ${IMAGES[$i]} -m ${MODULES[$i]} "
done

echo ${args}
