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

BPF_BUILD_SCRIPT_ENV = select({
    "//bazel:bpf_target_arch_aarch64": {
        "AYA_BPF_TARGET_ARCH": "aarch64",
    },
    "//conditions:default": {
        "AYA_BPF_TARGET_ARCH": "x86_64",
    },
})

BPF_C_TARGET_ARCH = select({
    "//bazel:bpf_target_arch_aarch64": "arm64",
    "//conditions:default": "x86",
})

BPF_RUSTC_FLAGS = select({
    "//bazel:bpf_target_arch_aarch64": [
        "--cfg=bpf_target_arch=\"aarch64\"",
    ],
    "//conditions:default": [
        "--cfg=bpf_target_arch=\"x86_64\"",
    ],
}) + [
    "-Cdebug-assertions=no",
    "-Cdebuginfo=2",
    "-Copt-level=3",
]

def _is_bpf_package(package_name):
    return package_name.startswith("ebpf/") or package_name in [
        "ebpf-panic",
        "test/integration-ebpf",
    ]

def _is_bpf_dep(dep):
    if not dep.startswith("//"):
        return False
    return _is_bpf_package(dep[2:].split(":")[0])

def _bpf_transition_impl(_, attr):
    return {
        "//command_line_option:platforms": str(attr.target_platform),
        "@rules_rust//rust/settings:no_std": "alloc",
    }

_bpf_transition = transition(
    implementation = _bpf_transition_impl,
    inputs = [],
    outputs = [
        "//command_line_option:platforms",
        "@rules_rust//rust/settings:no_std",
    ],
)

def _bpf_transition_filegroup_impl(ctx):
    files = []
    runfiles = ctx.runfiles()
    for src in ctx.attr.srcs:
        files.append(src[DefaultInfo].files)
        runfiles = runfiles.merge(src[DefaultInfo].default_runfiles)
    return [DefaultInfo(files = depset(transitive = files), runfiles = runfiles)]

bpf_transition_filegroup = rule(
    implementation = _bpf_transition_filegroup_impl,
    attrs = {
        "srcs": attr.label_list(
            allow_empty = False,
            cfg = _bpf_transition,
        ),
        "target_platform": attr.label(mandatory = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)

def _c_bpf_transition_impl(_, attr):
    return {
        "//command_line_option:platforms": str(attr._target_platform),
    }

_c_bpf_transition = transition(
    implementation = _c_bpf_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

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

    out = ctx.actions.declare_file(ctx.attr.out)
    outputs = [out]
    btf_out = None
    if ctx.attr.build_btf:
        if not ctx.attr.out.endswith(".o"):
            fail("aya_c_bpf_object out must end in .o when build_btf is set")
        btf_out = ctx.actions.declare_file(ctx.attr.out[:-2] + ".target.o")
        outputs.append(btf_out)

    compiled_object = _c_bpf_compile(ctx, cc_toolchain, feature_configuration, ctx.label.name)
    ctx.actions.symlink(
        output = out,
        target_file = compiled_object,
    )

    if btf_out:
        target_object = _c_bpf_compile(ctx, cc_toolchain, feature_configuration, ctx.label.name + "_target", defines = ["TARGET"])
        args = ctx.actions.args()
        args.add_all(["--dump-section", ".BTF=%s" % btf_out.path])
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

aya_c_bpf_object = rule(
    implementation = _c_bpf_object_impl,
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "out": attr.string(mandatory = True),
        "build_btf": attr.bool(default = False),
        "deps": attr.label_list(
            allow_empty = False,
            providers = [CcInfo],
        ),
        "hdrs": attr.label_list(allow_files = True),
        "target_arch": attr.string(default = "x86"),
        "vmlinux": attr.label(allow_single_file = True, mandatory = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
        "_llvm_objcopy": attr.label(
            allow_files = True,
            default = "@llvm//tools:llvm-objcopy",
            executable = True,
            cfg = "exec",
        ),
        "_target_platform": attr.label(default = "@llvm//platforms:none_bpfel"),
    },
    cfg = _c_bpf_transition,
    fragments = ["cpp"],
    toolchains = use_cc_toolchain(),
)

def _c_bpf_object_out(src):
    if not src.endswith(".c"):
        fail("C eBPF source must end in .c: %s" % src)
    return src.split("/")[-1][:-2] + ".o"

def _c_bpf_target_name(src):
    return _c_bpf_object_out(src)[:-2].replace("-", "_").replace(".", "_")

def aya_c_bpf_objects(name, objects, deps, hdrs, vmlinux, target_arch = "x86"):
    targets = []
    for src, build_btf in objects:
        target_name = _c_bpf_target_name(src)
        aya_c_bpf_object(
            name = target_name,
            build_btf = build_btf,
            deps = deps,
            hdrs = hdrs,
            out = _c_bpf_object_out(src),
            src = src,
            target_arch = target_arch,
            vmlinux = vmlinux,
        )
        targets.append(target_name)

    native.filegroup(
        name = name,
        srcs = targets,
    )

def _package_files():
    return native.glob(
        ["**"],
        exclude = [
            "**/BUILD",
            "**/BUILD.bazel",
            "bazel-*",
            "target/**",
        ],
        allow_empty = True,
    )

def _crate_name(name):
    return name.replace("-", "_")

def _dep_data(package_name = None):
    return DEP_DATA.get(package_name or native.package_name(), {})

def aya_crate_binaries(package_name = None):
    return _dep_data(package_name).get("binaries", {})

def aya_crate_binary_names(package_name = None):
    return sorted(aya_crate_binaries(package_name).keys())

def _crate_features(extra):
    dep_data = _dep_data()
    features = dep_data.get("crate_features", [])
    features_by_platform = dep_data.get("crate_features_by_platform", {})
    if features_by_platform:
        features = features + select(features_by_platform | {"//conditions:default": []})
    return features + extra

def aya_rust_crate(
        name,
        crate_name = None,
        proc_macro = False,
        build_script = True,
        build_script_env = {},
        crate_features = None,
        deps = None,
        rustc_env = {},
        rustc_flags = [],
        binary_rustc_flags = [],
        compile_data = [],
        unit_test = True,
        unit_test_binary = False,
        binary_unit_tests = None,
        test_deps = None,
        test_exec_properties = {},
        tags = [],
        test_tags = None,
        test_timeout = None,
        package_filegroup = True):
    package_name = native.package_name()
    is_bpf_package = _is_bpf_package(package_name)
    if is_bpf_package:
        build_script_env = BPF_BUILD_SCRIPT_ENV
        rustc_flags = BPF_RUSTC_FLAGS + rustc_flags

    package_files = _package_files()
    crate_features = _crate_features([]) if crate_features == None else crate_features
    binaries = aya_crate_binaries()
    if binary_unit_tests == None:
        binary_unit_tests = aya_crate_binary_names()
    if test_tags == None:
        test_tags = tags

    if package_filegroup:
        native.filegroup(
            name = "package-files",
            srcs = package_files,
            visibility = ["//visibility:public"],
        )

    build_script_deps = all_crate_deps(build = True)
    normal_deps = all_crate_deps() if deps == None else deps
    maybe_build_script = []
    if build_script and native.glob(["build.rs"], allow_empty = True):
        cargo_build_script(
            name = name + "-build-script",
            build_script_env = build_script_env,
            crate_name = "build_script_build",
            data = package_files,
            deps = build_script_deps,
            edition = "2024",
            rustc_env = rustc_env,
            srcs = ["build.rs"],
            tags = tags,
            version = "0.0.0",
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
            crate_name = crate_name or _crate_name(name),
            compile_data = package_files + compile_data,
            deps = lib_deps,
            edition = "2024",
            rustc_env = rustc_env,
            rustc_flags = rustc_flags,
            srcs = lib_srcs,
            tags = tags,
            visibility = ["//visibility:public"],
        )
        lib_target = ":" + name

    binary_deps = lib_deps + ([lib_target] if lib_target else [])
    for binary, crate_root in binaries.items():
        target_name = binary if binary != name else binary + "-bin"
        _rust_binary(
            name = target_name,
            crate_features = crate_features,
            crate_name = _crate_name(binary),
            crate_root = crate_root,
            compile_data = package_files + compile_data,
            deps = binary_deps,
            edition = "2024",
            rustc_env = rustc_env,
            rustc_flags = rustc_flags + binary_rustc_flags,
            srcs = native.glob(["src/**/*.rs"], allow_empty = True),
            tags = tags,
            visibility = ["//visibility:public"],
        )

    test_rule_deps = test_deps
    if test_rule_deps == None:
        test_rule_deps = all_crate_deps(normal = True, normal_dev = True)
        if not is_bpf_package and type(test_rule_deps) == type([]):
            test_rule_deps = [dep for dep in test_rule_deps if not _is_bpf_dep(dep)]
    test_rule_deps = test_rule_deps + maybe_build_script
    test_rule_kwargs = {
        "compile_data": package_files + compile_data,
        "crate_features": crate_features,
        "deps": test_rule_deps,
        "edition": "2024",
        "exec_properties": test_exec_properties,
        "rustc_env": rustc_env,
        "rustc_flags": rustc_flags,
        "tags": test_tags,
    }
    if test_timeout:
        test_rule_kwargs["timeout"] = test_timeout

    if unit_test and lib_target:
        _rust_test(
            name = name + "-unit-test",
            crate = lib_target,
            **test_rule_kwargs
        )

    if unit_test_binary and lib_target:
        if "src/lib.rs" not in lib_srcs:
            fail("unit_test_binary requires a src/lib.rs crate root")
        _rust_binary(
            name = name + "-unit-test-bin",
            compile_data = package_files + compile_data,
            crate_features = crate_features,
            crate_name = crate_name or _crate_name(name),
            crate_root = "src/lib.rs",
            deps = test_rule_deps,
            edition = "2024",
            rustc_env = rustc_env,
            rustc_flags = rustc_flags + ["--test"],
            srcs = lib_srcs,
            tags = tags,
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
