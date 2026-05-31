# Keep this congruent with `.github/workflows/ci.yml`.

# The clang shipped on macOS doesn't support BPF, so we need LLVM from brew.
brew "llvm"

brew "pkg-config"
brew "qemu"

# Required by libbpf-sys vendored dependencies.
brew "autoconf"
brew "automake"
brew "gawk"

# We need a musl C toolchain to compile our `test-distro` since some of our
# dependencies have build scripts that compile C code (i.e xz2).
tap  "filosottile/musl-cross"
brew "filosottile/musl-cross/musl-cross"
