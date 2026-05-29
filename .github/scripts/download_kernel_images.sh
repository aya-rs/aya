#!/usr/bin/env bash

set -euo pipefail

# Check for required arguments.
if [ "$#" -lt 3 ]; then
  echo "Usage: $0 <output directory> <architecture> <version1> [<version2> ...]"
  exit 1
fi

escape_regex() {
  # Escape characters that have special meaning in extended regular expressions so that
  # we can safely interpolate package names into grep patterns.
  printf '%s\n' "$1" | sed 's/[][(){}.^$*+?|\\-]/\\&/g'
}

snapshot_kernel_files() {
  local version=$1
  local architecture=$2
  local archive_timestamp
  local base
  local kernel_release
  local package_revision

  # Debian Snapshot does not have cloud packages for the current upstream LTS
  # tips (5.15.208 and 6.6.141 as of 2026-05-29). Use the newest archived
  # Debian cloud packages we can find for each LTS line instead: 5.15.15 for
  # 5.15, and 6.6.15 for 6.6.
  case "$version:$architecture" in
    5.15:amd64 | 5.15:arm64)
      archive_timestamp=20220130T155220Z
      kernel_release=5.15.0-3
      package_revision=5.15.15-2
      ;;
    6.6:amd64 | 6.6:arm64)
      archive_timestamp=20240206T163351Z
      kernel_release=6.6.15
      package_revision=6.6.15-2
      ;;
    *)
      return 1
      ;;
  esac

  base="https://snapshot.debian.org/archive/debian/${archive_timestamp}"
  base="${base}/pool/main/l/linux/linux-image-${kernel_release}-cloud-${architecture}"
  printf '%s\n' \
    "${base}-unsigned_${package_revision}_${architecture}.deb" \
    "${base}-dbg_${package_revision}_${architecture}.deb"
}

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
  if match=$(printf '%s\n' "$URLS" | grep -E "$REGEX" | sort -V | tail -n1); then
    FILES+=("$match")

    # The debug package contains the actual System.map. Debian has transitioned
    # between -dbg and -dbgsym suffixes, so match either for the specific kernel
    # we just selected.
    kernel_basename=$(basename "$match")
    kernel_prefix=${kernel_basename%%_*}
    kernel_suffix=${kernel_basename#${kernel_prefix}_}
    base_prefix=${kernel_prefix%-unsigned}

    base_prefix_regex=$(escape_regex "$base_prefix")
    kernel_suffix_regex=$(escape_regex "$kernel_suffix")

    DEBUG_REGEX="${base_prefix_regex}-dbg(sym)?_${kernel_suffix_regex}"
    debug_match=$(printf '%s\n' "$URLS" | grep -E "$DEBUG_REGEX" | sort -V | tail -n1) || {
      printf 'Failed to locate debug package matching %s\n%s\nVERSION=%s\nREGEX=%s\n' \
        "$kernel_basename" "$URLS" "$VERSION" "$DEBUG_REGEX" >&2
      exit 1
    }
    FILES+=("$debug_match")
  else
    snapshot_files=$(snapshot_kernel_files "$VERSION" "$ARCHITECTURE") || {
      printf '%s\nVERSION=%s\nREGEX=%s\n' "$URLS" "$VERSION" "$REGEX" >&2
      exit 1
    }
    while IFS= read -r FILE; do
      FILES+=("$FILE")
    done <<<"$snapshot_files"
  fi
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
