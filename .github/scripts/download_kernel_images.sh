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
  REGEX="linux-image-${VERSION//./\\.}\\.[0-9]+(-[0-9]+)?(\+bpo)?-cloud-${ARCHITECTURE}-unsigned_.*\\.deb"
  match=$(printf '%s\n' "$URLS" | grep -E "$REGEX" | sort -V | tail -n1) || {
    printf '%s\nVERSION=%s\nREGEX=%s\n' "$URLS" "$VERSION" "$REGEX" >&2
    exit 1
  }
  FILES+=("$match")
done

# TODO(https://github.com/curl/curl/issues/15729): restore --parallel here if and when it properly
# supports ETags.
# TODO(https://github.com/curl/curl/issues/15730): restore --create-dirs when it works in the
# presence of `--etag-save`.`
#
# Note: `--etag-{compare,save}` are not idempotent until curl 8.9.0 which included
# https://github.com/curl/curl/commit/85efbb92b8e6679705e122cee45ce76c56414a3e. At the time of
# writing our CI uses Ubuntu 22.04 which has curl 7.81.0 and the latest available is Ubuntu 24.04
# which has curl 8.5.0. Since neither has a new enough curl, we don't bother to update, but we
# should do so when Ubuntu 24.10 or later is available.
mkdir -p "$OUTPUT_DIR"
KEEP=()
for FILE in "${FILES[@]}"; do
  name=$(basename "$FILE")
  etag_name="$name.etag"
  KEEP+=("$name" "$etag_name")

  etag="$OUTPUT_DIR/$etag_name"
  curl -sfSL --output-dir "$OUTPUT_DIR" --remote-name-all --etag-compare "$etag" --etag-save "$etag" "$FILE"
done

# Remove any files that were previously downloaded that are no longer needed.
FIND_ARGS=()
for FILE in "${KEEP[@]}"; do
  FIND_ARGS+=("!" "-name" "$FILE")
done
find "$OUTPUT_DIR" -type f "${FIND_ARGS[@]}" -exec rm {} +
