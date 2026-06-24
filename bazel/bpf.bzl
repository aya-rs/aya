"""Aya Rust and C eBPF build rules."""

load("@rules_cc//cc:defs.bzl", "CcInfo")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@with_cfg.bzl", "with_cfg")

BPF_BUILD_SCRIPT_ENV = select({
    "//bazel:bpf_target_arch_aarch64": {
        "AYA_BPF_TARGET_ARCH": "aarch64",
    },
    "//bazel:bpf_target_arch_x86_64": {
        "AYA_BPF_TARGET_ARCH": "x86_64",
    },
})

_BPF_C_TARGET_ARCH = select({
    "//bazel:bpf_target_arch_aarch64": "arm64",
    "//bazel:bpf_target_arch_x86_64": "x86",
})

BPF_RUSTC_FLAGS = select({
    "//bazel:bpf_target_arch_aarch64": [
        "--cfg=bpf_target_arch=\"aarch64\"",
    ],
    "//bazel:bpf_target_arch_x86_64": [
        "--cfg=bpf_target_arch=\"x86_64\"",
    ],
}) + [
    "-Cdebug-assertions=no",
    "-Cdebuginfo=2",
    "-Copt-level=3",
]

def _bpf_filegroup(target_platform):
    # with_cfg applies the BPF target platform and no_std setting to the
    # filegroup and its transitive dependencies:
    # https://bazel.build/extending/config#user-defined-transitions
    return with_cfg(native.filegroup).set(
        "platforms",
        [target_platform],
    ).set(
        # rules_rust supports "alloc" as its only no_std mode; Aya uses core
        # only. Use core after rules_rust supports core-only no_std:
        # https://github.com/hermeticbuild/rules_rust/issues/28
        Label("@rules_rust//rust/settings:no_std"),
        "alloc",
    ).build()

# with_cfg requires its private rule classes to be exported by this module.
# buildifier: disable=unused-variable
_bpfeb_filegroup_macro, _bpfeb_filegroup_internal = _bpf_filegroup(Label("@rules_rs//rs/platforms:bpfeb-unknown-none"))

# buildifier: disable=unused-variable
_bpfel_filegroup_macro, _bpfel_filegroup_internal = _bpf_filegroup(Label("@rules_rs//rs/platforms:bpfel-unknown-none"))

def bpfeb_filegroup(name, srcs, **kwargs):
    """Applies the bpfeb-unknown-none platform to Rust eBPF binaries."""
    _bpfeb_filegroup_macro(name = name, srcs = srcs, **kwargs)

def bpfel_filegroup(name, srcs, **kwargs):
    """Applies the bpfel-unknown-none platform to Rust eBPF binaries."""
    _bpfel_filegroup_macro(name = name, srcs = srcs, **kwargs)

def _c_bpf_compile(ctx, cc_toolchain, feature_configuration, name, defines = []):
    _, compilation_outputs = cc_common.compile(
        actions = ctx.actions,
        name = name,
        feature_configuration = feature_configuration,
        cc_toolchain = cc_toolchain,
        srcs = [ctx.file.src],
        private_hdrs = ctx.files.hdrs + [ctx.file.vmlinux],
        includes = [ctx.file.vmlinux.dirname],
        quote_includes = [ctx.file.src.dirname],
        local_defines = ["__TARGET_ARCH_%s" % ctx.attr.target_arch] + defines,
        user_compile_flags = [
            "-g",
            "-O2",
        ],
        compilation_contexts = [
            dep[CcInfo].compilation_context
            for dep in ctx.attr.deps
        ],
        disallow_pic_outputs = True,
    )
    if len(compilation_outputs.objects) != 1:
        fail("expected exactly one C eBPF object, got %d" % len(compilation_outputs.objects))
    return compilation_outputs.objects[0]

def _c_bpf_object_impl(ctx):
    cc_toolchain = find_cc_toolchain(ctx)
    feature_configuration = cc_common.configure_features(
        ctx = ctx,
        cc_toolchain = cc_toolchain,
    )

    out_name = _c_bpf_object_out(ctx.file.src.basename)
    out = ctx.actions.declare_file(out_name)
    outputs = [out]
    btf_out = None
    if ctx.attr.build_btf:
        btf_out = ctx.actions.declare_file(out_name[:-2] + ".target.o")
        outputs.append(btf_out)

    compiled_object = _c_bpf_compile(ctx, cc_toolchain, feature_configuration, ctx.label.name)
    ctx.actions.symlink(
        output = out,
        target_file = compiled_object,
    )

    if btf_out:
        target_object = _c_bpf_compile(ctx, cc_toolchain, feature_configuration, ctx.label.name + "_target", defines = ["TARGET"])
        args = ctx.actions.args()
        args.add("--dump-section")
        args.add(btf_out, format = ".BTF=%s")
        args.add(target_object)
        ctx.actions.run(
            inputs = [target_object],
            outputs = [btf_out],
            executable = ctx.executable._llvm_objcopy,
            arguments = [args],
            mnemonic = "ExtractBtf",
            progress_message = "Extracting target BTF %{label}",
        )

    return [DefaultInfo(files = depset(outputs))]

_c_bpf_object_rule = rule(
    implementation = _c_bpf_object_impl,
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "build_btf": attr.bool(default = False),
        "deps": attr.label_list(
            allow_empty = False,
            providers = [CcInfo],
        ),
        "hdrs": attr.label_list(allow_files = True),
        "target_arch": attr.string(
            mandatory = True,
            values = ["arm64", "x86"],
        ),
        "vmlinux": attr.label(allow_single_file = True, mandatory = True),
        "_llvm_objcopy": attr.label(
            allow_files = True,
            default = "@llvm//tools:llvm-objcopy",
            executable = True,
            cfg = "exec",
        ),
    },
    fragments = ["cpp"],
    toolchains = use_cc_toolchain(),
)

# with_cfg requires its private rule class to be exported by this module.
# buildifier: disable=unused-variable
_c_bpf_object, _c_bpf_object_internal = with_cfg(_c_bpf_object_rule).set(
    "platforms",
    [Label("@llvm//platforms:none_bpfel")],
).build()
# buildifier: enable=unused-variable

def _c_bpf_object_out(src):
    if not src.endswith(".c"):
        fail("C eBPF source must end in .c: %s" % src)
    return src.split("/")[-1][:-2] + ".o"

def _c_bpf_target_name(src):
    return _c_bpf_object_out(src)[:-2].replace("-", "_").replace(".", "_")

def aya_c_bpf_objects(name, objects, deps, hdrs, vmlinux):
    """Compiles integration-test C eBPF inputs and collects their objects.

    Args:
      name: Name of the resulting filegroup.
      objects: List of `(src, build_btf)` tuples.
      deps: C dependencies for every source.
      hdrs: C headers for every source.
      vmlinux: `vmlinux.h` label for every source.
    """
    targets = []
    for src, build_btf in objects:
        target_name = _c_bpf_target_name(src)
        _c_bpf_object(
            name = target_name,
            build_btf = build_btf,
            deps = deps,
            hdrs = hdrs,
            src = src,
            target_arch = _BPF_C_TARGET_ARCH,
            vmlinux = vmlinux,
        )
        targets.append(target_name)

    native.filegroup(
        name = name,
        srcs = targets,
    )
