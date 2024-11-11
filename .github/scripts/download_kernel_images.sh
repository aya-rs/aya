#!/usr/bin/env bash

set -euo pipefail

# Check for required arguments.
if [ "$#" -lt 3 ]; then
  echo "Usage: $0 <output directory> <architecture> <version1> [<version2> ...]"
  exit 1
fi

OUTPUT_DIR=$1
ARCHITECTURE=$2
shift 2
VERSIONS=("$@")

URLS=$(lynx -dump -listonly -nonumbers https://mirrors.wikimedia.org/debian/pool/main/l/linux/)
readonly URLS

# Find the latest revision of each kernel version.
FILES=()
for VERSION in "${VERSIONS[@]}"; do
  while read -r line; do
    FILES+=("$line")
  done <<< "$(
    printf '%s\n' "$URLS" \
    | grep -E "linux-image-${VERSION//./\\.}\\.[0-9]+(-[0-9]+)?-cloud-${ARCHITECTURE}-unsigned_.*\\.deb" \
    | sort -V \
    | tail -n1
  )"
done

printf '%s\n' "${FILES[@]}" \
| xargs -t curl -sfSL --create-dirs --output-dir "$OUTPUT_DIR" --parallel --remote-name-all
