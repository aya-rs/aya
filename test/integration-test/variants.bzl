"""Configure native integration architecture and optimized test binaries."""

load("@with_cfg.bzl", "with_cfg")

# Build the test harness and its dependencies in opt mode while sharing the
# source-built kernel image with the fastbuild harness.
# buildifier: disable=unused-variable
opt_filegroup, _opt_filegroup_internal = with_cfg(native.filegroup).set("compilation_mode", "opt").build()

# buildifier: disable=unused-variable
host_arch_filegroup, _host_arch_filegroup_internal = with_cfg(native.filegroup).set(
    Label("//bazel:bpf_target_arch"),
    select({
        "@platforms//cpu:aarch64": "aarch64",
        "@platforms//cpu:x86_64": "x86_64",
    }),
).build()
