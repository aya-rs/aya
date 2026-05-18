# Bazel Kernel Inputs

The `aya_*.config` files are allnoconfig-based Kconfig fragments for the
Bazel-native `linux.bzl` build. They intentionally do not mirror Debian kernel
configs; they are explicit allowlists for the kernel features required by the
integration tests.

When a test needs another kernel feature, prefer proving that need with a VM
test failure and then adding the narrowest corresponding Kconfig option here.
