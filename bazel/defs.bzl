"""Aya Rust and BPF build rules."""

load("@crates//:data.bzl", "DEP_DATA")
load("@crates//:defs.bzl", "all_crate_deps")
load("@rules_cc//cc:defs.bzl", "CcInfo")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_rs//rs:cargo_build_script.bzl", "cargo_build_script")
load(
    "@rules_rust//rust:defs.bzl",
    _rust_binary = "rust_binary",
    _rust_library = "rust_library",
    _rust_proc_macro = "rust_proc_macro",
    _rust_test = "rust_test",
)
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

bpfeb_filegroup, _bpfeb_filegroup_internal = _bpf_filegroup(Label("@rules_rs//rs/platforms:bpfeb-unknown-none"))
bpfel_filegroup, _bpfel_filegroup_internal = _bpf_filegroup(Label("@rules_rs//rs/platforms:bpfel-unknown-none"))

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
    """Compiles C BPF sources and collects their object files in a filegroup.

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

def _crate_name(name):
    return name.replace("-", "_")

def _dep_data():
    return DEP_DATA.get(native.package_name(), {})

def _crate_binaries():
    return _dep_data().get("binaries", {})

def aya_crate_binary_names():
    return sorted(_crate_binaries().keys())

def _crate_features():
    dep_data = _dep_data()
    features = dep_data.get("crate_features", [])
    features_by_platform = dep_data.get("crate_features_by_platform", {})
    if features_by_platform:
        features = features + select(features_by_platform | {"//conditions:default": []})
    return features

def aya_rust_crate(
        name,
        ebpf = False,
        proc_macro = False,
        build_script = True,
        crate_features = None,
        deps = None,
        rustc_env = {},
        binary_rustc_flags = [],
        compile_data = [],
        binary_unit_tests = None,
        test_deps = None,
        test_binary = False):
    """Declares Rust targets for the Cargo package in the current package.

    Args:
      name: Cargo package name and primary Bazel target name.
      ebpf: Whether to compile the package for a BPF target.
      proc_macro: Whether the package library is a procedural macro.
      build_script: Whether to declare a detected `build.rs` target.
      crate_features: Cargo features, or generated features when unset.
      deps: Library dependencies, or generated dependencies when unset.
      rustc_env: Environment variables for Rust compilation.
      binary_rustc_flags: Additional rustc flags for binary targets.
      compile_data: Runtime files available during Rust compilation.
      binary_unit_tests: Binary names to test, or every binary when unset.
      test_deps: Test dependencies, or generated dependencies when unset.
      test_binary: Whether to expose the library test harness as a binary.
    """
    build_script_env = BPF_BUILD_SCRIPT_ENV if ebpf else {}
    rustc_flags = BPF_RUSTC_FLAGS if ebpf else []
    crate_features = _crate_features() if crate_features == None else crate_features
    binaries = _crate_binaries()
    if binary_unit_tests == None:
        binary_unit_tests = aya_crate_binary_names()

    normal_deps = all_crate_deps() if deps == None else deps
    maybe_build_script = []
    build_script_srcs = native.glob(["build.rs"], allow_empty = True) if build_script else []
    if build_script_srcs:
        cargo_build_script(
            name = name + "-build-script",
            build_script_env = build_script_env,
            crate_name = "build_script_build",
            deps = all_crate_deps(build = True),
            edition = "2024",
            rustc_env = rustc_env,
            srcs = build_script_srcs,
        )
        maybe_build_script = [":" + name + "-build-script"]

    lib_srcs = native.glob(
        ["src/**/*.rs"],
        exclude = binaries.values(),
        allow_empty = True,
    )
    lib_deps = normal_deps + maybe_build_script
    lib_target = None
    if lib_srcs:
        lib_rule = _rust_proc_macro if proc_macro else _rust_library
        lib_rule(
            name = name,
            crate_features = crate_features,
            crate_name = _crate_name(name),
            compile_data = compile_data,
            deps = lib_deps,
            edition = "2024",
            rustc_env = rustc_env,
            rustc_flags = rustc_flags,
            srcs = lib_srcs,
            visibility = ["//visibility:public"],
        )
        lib_target = name

    binary_deps = lib_deps + ([lib_target] if lib_target else [])
    for binary, crate_root in binaries.items():
        target_name = binary if binary != name else binary + "-bin"
        _rust_binary(
            name = target_name,
            crate_features = crate_features,
            crate_name = _crate_name(binary),
            crate_root = crate_root,
            compile_data = compile_data,
            deps = binary_deps,
            edition = "2024",
            rustc_env = rustc_env,
            rustc_flags = rustc_flags + binary_rustc_flags,
            srcs = native.glob(["src/**/*.rs"], allow_empty = True),
            tags = ["manual"] if ebpf else [],
            visibility = ["//visibility:public"],
        )

    test_rule_deps = all_crate_deps(normal = True, normal_dev = True) if test_deps == None else test_deps
    test_rule_deps = test_rule_deps + maybe_build_script
    test_rule_kwargs = {
        "compile_data": compile_data,
        "crate_features": crate_features,
        "deps": test_rule_deps,
        "edition": "2024",
        "rustc_env": rustc_env,
        "rustc_flags": rustc_flags,
    }

    if lib_target:
        if test_binary:
            if "src/lib.rs" not in lib_srcs:
                fail("test_binary requires a src/lib.rs crate root")
            _rust_binary(
                name = name + "-unit-test",
                crate_features = crate_features,
                crate_name = _crate_name(name),
                crate_root = "src/lib.rs",
                compile_data = compile_data,
                deps = test_rule_deps,
                edition = "2024",
                rustc_env = rustc_env,
                rustc_flags = rustc_flags + ["--test"],
                srcs = lib_srcs,
            )
        else:
            _rust_test(
                name = name + "-unit-test",
                crate = lib_target,
                **test_rule_kwargs
            )

    for binary in binary_unit_tests:
        target_name = binary if binary != name else binary + "-bin"
        binary_test_rule_kwargs = dict(test_rule_kwargs)
        if lib_target:
            binary_test_deps = test_rule_deps + [lib_target]
            binary_test_rule_kwargs["deps"] = binary_test_deps

        _rust_test(
            name = target_name + "-unit-test",
            crate_name = _crate_name(binary),
            crate_root = binaries[binary],
            srcs = native.glob(["src/**/*.rs"], allow_empty = True),
            **binary_test_rule_kwargs
        )
