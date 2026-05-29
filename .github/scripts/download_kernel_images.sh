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

SNAPSHOT_URL=https://snapshot.debian.org

urlencode() {
  jq -rn --arg value "$1" '$value|@uri'
}

# Debian Snapshot machine-readable API:
# https://salsa.debian.org/snapshot-team/snapshot/raw/master/API
snapshot_api() {
  curl -fsSL --retry 3 --retry-all-errors --retry-delay 1 \
    -H 'User-Agent: aya-download-kernel-images' \
    "${SNAPSHOT_URL}/mr/$1"
}

snapshot_file_url() {
  local binary_name=$1
  local binary_version=$2
  local architecture=$3
  local binary_name_url
  local binary_version_url
  local file_hash
  local file_url

  binary_name_url=$(urlencode "$binary_name")
  binary_version_url=$(urlencode "$binary_version")
  # Resolve the binary package to a concrete .deb file hash.
  file_hash=$(snapshot_api "binary/${binary_name_url}/${binary_version_url}/binfiles" | jq -r \
    --arg architecture "$architecture" \
    '[.result[] | select(.architecture == $architecture) | .hash][0] // empty')

  if [ -z "$file_hash" ]; then
    printf 'Failed to locate %s file for %s=%s\n' "$architecture" "$binary_name" "$binary_version" >&2
    return 1
  fi

  # Resolve the file hash to the archive timestamp and path used for download.
  file_url=$(snapshot_api "file/${file_hash}/info" | jq -r \
    --arg snapshot_url "$SNAPSHOT_URL" \
    '([.result[] | select(.archive_name == "debian")][0]) as $file |
     if $file then
       "\($snapshot_url)/archive/\($file.archive_name)/\($file.first_seen)\($file.path)/\($file.name|@uri)"
     else
       empty
     end')

  if [ -z "$file_url" ]; then
    printf 'Failed to locate Debian archive entry for %s=%s\n' "$binary_name" "$binary_version" >&2
    return 1
  fi

  printf '%s\n' "$file_url"
}

snapshot_kernel_files() {
  local version=$1
  local architecture=$2
  local version_regex
  local source_versions

  # Current Debian mirrors only expose recent linux packages. When an older
  # kernel line ages out, query Debian Snapshot for the newest archived source
  # version that still has matching cloud image and debug packages.
  version_regex=$(escape_regex "$version")
  # Step 1: list Debian linux source versions matching the requested kernel
  # major.minor version, newest first.
  source_versions=$(snapshot_api package/linux/ | jq -r '.result[].version' \
    | { grep -E "^${version_regex}\.[0-9]+-[0-9]+$" || true; } \
    | sort -Vr)

  while IFS= read -r source_version; do
    local base_name
    local debug_name
    local debug_url
    local kernel_name
    local kernel_names
    local kernel_url
    local packages
    local source_version_url

    [ -n "$source_version" ] || continue

    source_version_url=$(urlencode "$source_version")
    # Step 2: inspect binaries built by this source version to find the real
    # cloud image package name. The name is not always derivable from the source
    # version; for example, 5.15.15-2 built linux-image-5.15.0-3-cloud-amd64.
    packages=$(snapshot_api "package/linux/${source_version_url}/binpackages")
    kernel_names=$(printf '%s\n' "$packages" | jq -r \
      --arg source_version "$source_version" \
      --arg suffix "-cloud-${architecture}-unsigned" \
      '.result[]
       | select(.version == $source_version)
       | select(.name | startswith("linux-image-"))
       | select(.name | endswith($suffix))
       | .name' | sort -V)

    while IFS= read -r kernel_name; do
      [ -n "$kernel_name" ] || continue

      base_name=${kernel_name%-unsigned}
      # Step 3: require the matching debug package for System.map.
      debug_name=$(printf '%s\n' "$packages" | jq -r \
        --arg source_version "$source_version" \
        --arg dbg "${base_name}-dbg" \
        --arg dbgsym "${base_name}-dbgsym" \
        '[.result[]
          | select(.version == $source_version)
          | select(.name == $dbg or .name == $dbgsym)
          | .name][0] // empty')
      [ -n "$debug_name" ] || continue

      kernel_url=$(snapshot_file_url "$kernel_name" "$source_version" "$architecture") || return 1
      debug_url=$(snapshot_file_url "$debug_name" "$source_version" "$architecture") || return 1
      printf '%s\n%s\n' "$kernel_url" "$debug_url"
      return 0
    done <<<"$kernel_names"
  done <<<"$source_versions"

  printf 'Failed to find Debian Snapshot cloud kernel packages for %s/%s\n' \
    "$version" "$architecture" >&2
  return 1
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
    # If the requested kernel line is no longer listed in the current Debian
    # pool, use Debian Snapshot as a historical fallback.
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
