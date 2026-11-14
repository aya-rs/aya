"""Generate and update Aya bindings with declared tools and headers."""

load("@bazel_skylib//rules:diff_test.bzl", "diff_test")
load("@bazel_skylib//rules/directory:providers.bzl", "DirectoryInfo")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
load(":codegen_architectures.bzl", "CODEGEN_ARCHITECTURES")

def _bindings_impl(ctx):
    libc = ctx.attr.libc_headers[DirectoryInfo]
    kernel = ctx.attr.kernel_headers[DirectoryInfo]
    libbpf = ctx.attr._libbpf_headers
    rustfmt = ctx.toolchains["@rules_rust//rust/rustfmt:toolchain_type"]
    dynamic_libraries = []
    for linker_input in ctx.attr._libclang[CcInfo].linking_context.linker_inputs.to_list():
        for library in linker_input.libraries:
            if library.dynamic_library:
                dynamic_libraries.append(library.dynamic_library)
    if len(dynamic_libraries) != 1:
        fail("libclang must provide exactly one shared library, got {}".format(dynamic_libraries))
    libclang = dynamic_libraries[0]

    outputs = [ctx.outputs.aya, ctx.outputs.ebpf, ctx.outputs.helpers, ctx.outputs.btf]
    args = ctx.actions.args()
    args.add("codegen")
    args.add("--target", ctx.attr.target)
    args.add("--libc-headers", libc.path)
    args.add("--kernel-headers", kernel.path)
    args.add("--libbpf-dir", libbpf.label.workspace_root)
    args.add("--builtin-headers", ctx.file._builtin_anchor.dirname)
    args.add("--aya-header", ctx.file._aya_header)
    args.add("--ebpf-header", ctx.file._ebpf_header)
    args.add("--aya-output", ctx.outputs.aya)
    args.add("--ebpf-output", ctx.outputs.ebpf)
    args.add("--helpers-output", ctx.outputs.helpers)
    args.add("--btf-output", ctx.outputs.btf)
    args.add("--rustfmt", rustfmt.rustfmt)
    args.add("--rustfmt-config", ctx.file._rustfmt_config)
    libelf = ctx.attr._libelf[CcInfo].compilation_context
    args.add_all(libelf.includes, format_each = "--elf-clang-arg=-I%s")
    args.add_all(libelf.quote_includes, format_each = "--elf-clang-arg=-iquote%s")
    args.add_all(libelf.system_includes, format_each = "--elf-clang-arg=-isystem%s")
    args.add_all(libelf.external_includes, format_each = "--elf-clang-arg=-isystem%s")

    ctx.actions.run(
        executable = ctx.executable._generator,
        arguments = [args],
        env = {"LIBCLANG_PATH": libclang.path},
        inputs = depset(
            [ctx.file._aya_header, ctx.file._ebpf_header, ctx.file._rustfmt_config, libclang],
            transitive = [
                libc.transitive_files,
                kernel.transitive_files,
                libbpf[DefaultInfo].files,
                libelf.headers,
                ctx.attr._builtin_headers[DefaultInfo].files,
                ctx.attr._libclang[DefaultInfo].default_runfiles.files,
            ],
        ),
        tools = [ctx.attr._generator[DefaultInfo].files_to_run, rustfmt.all_files],
        outputs = outputs,
        mnemonic = "AyaBindings",
        progress_message = "Generating Aya bindings for {}".format(ctx.attr.target),
        toolchain = "@rules_rust//rust/rustfmt:toolchain_type",
    )
    return [DefaultInfo(files = depset(outputs))]

_bindings = rule(
    implementation = _bindings_impl,
    attrs = {
        "aya": attr.output(mandatory = True),
        "btf": attr.output(mandatory = True),
        "ebpf": attr.output(mandatory = True),
        "helpers": attr.output(mandatory = True),
        "kernel_headers": attr.label(mandatory = True, providers = [DirectoryInfo]),
        "libc_headers": attr.label(mandatory = True, providers = [DirectoryInfo]),
        "target": attr.string(mandatory = True),
        "_aya_header": attr.label(default = "//aya-obj:include/linux_wrapper.h", allow_single_file = True),
        "_builtin_anchor": attr.label(default = "@llvm-project//clang:staging/include/stddef.h", cfg = "exec", allow_single_file = True),
        "_builtin_headers": attr.label(default = "@llvm-project//clang:builtin_headers_gen", cfg = "exec"),
        "_ebpf_header": attr.label(default = "//ebpf/aya-ebpf-bindings:include/bindings.h", allow_single_file = True),
        "_generator": attr.label(default = "//xtask:xtask-bin", cfg = "exec", executable = True),
        "_libbpf_headers": attr.label(default = "@libbpf//:source_headers"),
        "_libclang": attr.label(default = "@llvm-project//clang:libclang", cfg = "exec", providers = [CcInfo]),
        "_libelf": attr.label(default = "@elfutils//:libelf", cfg = "exec", providers = [CcInfo]),
        "_rustfmt_config": attr.label(default = "//:rustfmt.toml", allow_single_file = True),
    },
    toolchains = ["@rules_rust//rust/rustfmt:toolchain_type"],
)

def aya_bindings(name):
    """Declare the nine architecture-specific generator actions.

    Args:
      name: Prefix for the architecture-specific target names.
    """
    btf_tests = []
    for arch, (target, _libc_arch, _kernel_arch) in CODEGEN_ARCHITECTURES.items():
        btf = "generated/%s/btf_internal_bindings.rs" % arch
        _bindings(
            name = "%s_%s" % (name, arch),
            target = target,
            libc_headers = "@codegen_headers//:%s_glibc" % arch,
            kernel_headers = "@codegen_headers//:%s_kernel" % arch,
            aya = "generated/linux_bindings_%s.rs" % arch,
            ebpf = "generated/%s/bindings.rs" % arch,
            helpers = "generated/%s/helpers.rs" % arch,
            btf = btf,
            tags = ["manual"],
            visibility = ["//visibility:public"],
        )

        # aya-obj ships one copy of these BTF records for all architectures.
        # Its updater takes the x86_64 output; check the others agree with it.
        if arch != "x86_64":
            test = "%s_%s_btf_test" % (name, arch)
            diff_test(
                name = test,
                file1 = "generated/x86_64/btf_internal_bindings.rs",
                file2 = btf,
                tags = ["manual"],
            )
            btf_tests.append(test)

    native.test_suite(
        name = "%s_btf_tests" % name,
        tests = btf_tests,
        tags = ["manual"],
    )
