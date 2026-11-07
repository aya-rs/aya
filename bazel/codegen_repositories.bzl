"""Pinned libc and kernel headers for source binding generation."""

load(":codegen_architectures.bzl", "CODEGEN_ARCHITECTURES")

def _headers_impl(ctx):
    # Match the glibc and kernel-header series used by Ubuntu 24.04 codegen.
    # Read the checked-in LLVM indices instead of maintaining another hash list.
    glibc = json.decode(ctx.read(ctx.attr._glibc_index))["2.39"]
    kernel = json.decode(ctx.read(ctx.attr._kernel_index))["6.8.12"]
    downloaded = {}
    targets = []
    for arch, (_target, libc_arch, kernel_arch) in CODEGEN_ARCHITECTURES.items():
        for kind, header_arch, index in [("glibc", libc_arch, glibc), ("kernel", kernel_arch, kernel)]:
            path = "%s/%s" % (kind, header_arch)
            if path not in downloaded:
                entry = index[header_arch]
                ctx.download_and_extract(
                    url = entry["url"],
                    sha256 = entry["sha256"],
                    stripPrefix = header_arch,
                    output = path,
                )
                downloaded[path] = True
            targets.append("""subdirectory(
    name = "{arch}_{kind}",
    parent = ":files",
    path = "{path}/include",
    visibility = ["//visibility:public"],
)
""".format(arch = arch, kind = kind, path = path))

    ctx.file("BUILD.bazel", """load("@bazel_skylib//rules/directory:directory.bzl", "directory")
load("@bazel_skylib//rules/directory:subdirectory.bzl", "subdirectory")

directory(name = "files", srcs = glob(["glibc/**", "kernel/**"]))

{targets}""".format(targets = "\n".join(targets)))
    return ctx.repo_metadata(reproducible = True)

_headers = repository_rule(
    implementation = _headers_impl,
    attrs = {
        "_glibc_index": attr.label(default = "@llvm//runtimes/glibc/extension:glibc_headers_index.json"),
        "_kernel_index": attr.label(default = "@llvm//kernel/extension:kernel_headers_index.json"),
    },
)

def _codegen_headers_impl(ctx):
    _headers(name = "codegen_headers")
    return ctx.extension_metadata(
        reproducible = True,
        root_module_direct_deps = ["codegen_headers"],
        root_module_direct_dev_deps = [],
    )

codegen_headers = module_extension(implementation = _codegen_headers_impl)
