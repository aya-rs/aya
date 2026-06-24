"""Aya Rust package build rules."""

load("@crates//:data.bzl", "DEP_DATA")
load("@crates//:defs.bzl", "all_crate_deps")
load("@rules_rs//rs:cargo_build_script.bzl", "cargo_build_script")
load(
    "@rules_rust//rust:defs.bzl",
    _rust_binary = "rust_binary",
    _rust_library = "rust_library",
    _rust_proc_macro = "rust_proc_macro",
    _rust_test = "rust_test",
)
load("//bazel:bpf.bzl", "BPF_BUILD_SCRIPT_ENV", "BPF_RUSTC_FLAGS")

def _crate_name(name):
    return name.replace("-", "_")

def aya_crate_binary_names():
    return sorted(DEP_DATA.get(native.package_name(), {}).get("binaries", {}).keys())

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
        test_binary = False):
    """Reads rules_rs metadata and declares one Cargo package's Rust targets.

    Args:
      name: Cargo package name and primary Bazel target name.
      ebpf: Whether to compile the package for an eBPF target.
      proc_macro: Whether the package library is a procedural macro.
      build_script: Whether to declare a detected `build.rs` target.
      crate_features: Cargo features, or generated features when unset.
      deps: Library dependencies, or generated dependencies when unset.
      rustc_env: Environment variables for Rust compilation.
      binary_rustc_flags: Additional rustc flags for binary targets.
      compile_data: Runtime files available during Rust compilation.
      binary_unit_tests: Binary names to test, or every binary when unset.
      test_binary: Whether to expose the library test harness as a binary.
    """
    build_script_env = BPF_BUILD_SCRIPT_ENV if ebpf else {}
    rustc_flags = BPF_RUSTC_FLAGS if ebpf else []
    dep_data = DEP_DATA.get(native.package_name(), {})
    binaries = dep_data.get("binaries", {})
    if crate_features == None:
        crate_features = dep_data.get("crate_features", [])
        features_by_platform = dep_data.get("crate_features_by_platform", {})
        if features_by_platform:
            crate_features = crate_features + select(features_by_platform | {"//conditions:default": []})
    if binary_unit_tests == None:
        binary_unit_tests = sorted(binaries.keys())

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

    test_rule_deps = all_crate_deps(normal = True, normal_dev = True) + maybe_build_script
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
            binary_test_rule_kwargs["deps"] = test_rule_deps + [lib_target]

        _rust_test(
            name = target_name + "-unit-test",
            crate_name = _crate_name(binary),
            crate_root = binaries[binary],
            srcs = native.glob(["src/**/*.rs"], allow_empty = True),
            **binary_test_rule_kwargs
        )
