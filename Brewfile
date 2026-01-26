# Keep this congruent with `.github/workflows/ci.yml`.

# The curl shipped on macOS doesn't contain
# https://github.com/curl/curl/commit/85efbb92b8e6679705e122cee45ce76c56414a3e
# which is needed for proper handling of `--etag-{compare,save}`.
brew "curl"

# The clang shipped on macOS doesn't support BPF, so we need LLVM from brew.
brew "llvm"

brew "lynx"
brew "pkg-config"
brew "qemu"

brew "autoconf" # "autoreconf is required to compile libbpf-sys with the selected set of features"
brew "automake" # "aclocal (part of automake) is required by elfutils autoreconf"
brew "gawk" # "gawk is required to compile libbpf-sys with the selected set of features"

# macOS provides only dynamic zlib. Install the static one.
brew "zlib"

# We need a musl C toolchain to compile our `test-distro` since some of our
# dependencies have build scripts that compile C code (i.e xz2).
tap  "filosottile/musl-cross"
brew "filosottile/musl-cross/musl-cross"
