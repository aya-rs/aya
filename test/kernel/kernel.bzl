"""Build the kernel artifacts required by Aya's integration VMs."""

load("@linux.bzl//rules:artifact.bzl", "kernel_artifact")
load("@linux.bzl//rules:config.bzl", "kernel_config")
load("@linux.bzl//rules:kernel.bzl", "kernel_build")
load("@linux.bzl//rules:source.bzl", "kernel_source")

KERNEL_LINES = [
    "5_10",
    "5_15",
    "6_1",
    "6_6",
    "6_12",
    "6_18",
]

def aya_kernel(name, sources, anchor, syntax):
    """Declare a kernel build for the selected guest platform.

    Args:
      name: Boot image target; the other targets use this name as a prefix.
      sources: Raw Linux source files.
      anchor: The source tree's top-level Makefile.
      syntax: Symbolic Make syntax exported from that same source tree.
    """
    source = name + "_source"
    kernel_source(
        name = source,
        anchor = anchor,
        sources = sources,
        tags = ["manual"],
    )
    config = name + "_configuration"
    kernel_config(
        name = config,
        fragments = select({
            "@platforms//cpu:aarch64": [Label("//test/kernel:aya_aarch64.config")],
            "@platforms//cpu:x86_64": [Label("//test/kernel:aya_x86_64.config")],
        }),
        mode = "allnoconfig",
        pahole = Label("@pahole//:pahole"),
        source = ":" + source,
        tags = ["manual"],
    )

    boot_images = {
        "@platforms//cpu:aarch64": "arch/arm64/boot/Image",
        "@platforms//cpu:x86_64": "arch/x86/boot/bzImage",
    }
    module = "net/sched/sch_ingress.ko"
    build = name + "_build"
    kernel_build(
        name = build,
        config = ":" + config,
        required_options = {
            "BPF_LSM": "y",
            "DEBUG_INFO_BTF": "y",
            "EPOLL": "y",
            "MULTIUSER": "y",
            "NAMESPACES": "y",
            "NET_CLS_BPF": "y",
            "NET_NS": "y",
            "NET_SCH_INGRESS": "m",
            "SECURITY": "y",
            "SECURITY_NETWORK": "y",
            "SHMEM": "y",
            "SMP": "y",
            "TMPFS": "y",
            "USER_NS": "y",
            "XDP_SOCKETS": "y",
        },
        roots = [
            "vmlinux",
            module,
        ] + select({platform: [path] for platform, path in boot_images.items()}),
        syntax = syntax,
        tags = ["manual"],
    )
    kernel_artifact(
        name = name,
        kernel = ":" + build,
        path = select(boot_images),
        tags = ["manual"],
    )
    for suffix, path in {
        "config": ".config",
        "system_map": "System.map",
        "sch_ingress": module,
    }.items():
        kernel_artifact(
            name = name + "_" + suffix,
            kernel = ":" + build,
            path = path,
            tags = ["manual"],
        )
