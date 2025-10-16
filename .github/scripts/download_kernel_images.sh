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
  REGEX="linux-image-${VERSION//./\\.}\\.[0-9]+(-[0-9]+)?(\+bpo|\+deb[0-9]+)?-cloud-${ARCHITECTURE}-unsigned_.*\\.deb"
  match=$(printf '%s\n' "$URLS" | grep -E "$REGEX" | sort -V | tail -n1) || {
    printf '%s\nVERSION=%s\nREGEX=%s\n' "$URLS" "$VERSION" "$REGEX" >&2
    exit 1
  }
  FILES+=("$match")

  # The debug package contains the actual System.map. Debian has transitioned
  # between -dbg and -dbgsym suffixes, so match either for the specific kernel
  # we just selected.
  kernel_basename=$(basename "$match")
  kernel_prefix=${kernel_basename%%_*}
  kernel_suffix=${kernel_basename#${kernel_prefix}_}
  base_prefix=${kernel_prefix%-unsigned}

  base_prefix_regex=$(printf '%s\n' "$base_prefix" | sed 's/[][(){}.^$*+?|\\-]/\\&/g')
  kernel_suffix_regex=$(printf '%s\n' "$kernel_suffix" | sed 's/[][(){}.^$*+?|\\-]/\\&/g')

  DEBUG_REGEX="${base_prefix_regex}-dbg(sym)?_${kernel_suffix_regex}"
  debug_match=$(printf '%s\n' "$URLS" | grep -E "$DEBUG_REGEX" | sort -V | tail -n1) || {
    printf 'Failed to locate debug package matching %s\n%s\nVERSION=%s\nREGEX=%s\n' \
      "$kernel_basename" "$URLS" "$VERSION" "$DEBUG_REGEX" >&2
    exit 1
  }
  FILES+=("$debug_match")
done

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
