"""Hermetic VM helpers for integration tests."""

load("@bazel_lib//lib:transitions.bzl", "platform_transition_filegroup")

_QEMU_SYSTEM_TOOLCHAIN_TYPE = "@rules_qemu//qemu:system_toolchain_type"

_GUESTS = {
    "aarch64": struct(
        cpu = "neoverse-n1",  # QEMU "max" has broken aarch64 CI before.
        kernel_args = "console=ttyAMA0 lsm=bpf panic=-1",
        platform = "@rules_rs//rs/platforms:aarch64-unknown-linux-musl",
        smp = "2",
    ),
    "x86_64": struct(
        cpu = "max",
        kernel_args = "console=ttyS0,115200n8 rdinit=/init lsm=bpf panic=-1",
        platform = "@rules_rs//rs/platforms:x86_64-unknown-linux-musl",
        smp = "1",
    ),
}

def _target_arch_transition_impl(_, attr):
    return {"//bazel:bpf_target_arch": attr.qemu_system_target}

_target_arch_transition = transition(
    implementation = _target_arch_transition_impl,
    inputs = [],
    outputs = ["//bazel:bpf_target_arch"],
)

def _rootpath(file, workspace_name):
    short_path = file.short_path
    if short_path.startswith("../"):
        return short_path[3:]
    return workspace_name + "/" + short_path

def _aya_qemu_vm_test_impl(ctx):
    kernel = ctx.file.kernel
    initrd = ctx.file.initrd
    qemu = ctx.toolchains[_QEMU_SYSTEM_TOOLCHAIN_TYPE]
    guest = _GUESTS[qemu.target_arch]
    script = ctx.actions.declare_file(ctx.label.name + ".sh")

    qemu_args = [
        "-machine",
        qemu.machine,
        "-cpu",
        guest.cpu,
        "-accel",
        "kvm",
        "-accel",
        "tcg",
        "-no-reboot",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-m",
        "1024M",
        "-smp",
        guest.smp,
    ]

    ctx.actions.write(
        output = script,
        is_executable = True,
        content = """#!/usr/bin/env bash
set -euo pipefail

qemu="${{TEST_SRCDIR}}/{qemu}"
qemu_data_dir="${{TEST_SRCDIR}}/{qemu_data_dir}"
kernel="${{TEST_SRCDIR}}/{kernel}"
initrd="${{TEST_SRCDIR}}/{initrd}"

kernel_args="{kernel_args}"
for arg in "$@"; do
  kernel_args="${{kernel_args}} init.arg=${{arg}}"
done

log="${{TEST_TMPDIR:-/tmp}}/{name}.qemu.log"

"${{qemu}}" {qemu_args} -L "${{qemu_data_dir}}" -append "${{kernel_args}}" -kernel "${{kernel}}" -initrd "${{initrd}}" >"${{log}}" 2>&1 &
qemu_pid="$!"
timeout_seconds="${{TEST_TIMEOUT:-300}}"
deadline=$((SECONDS + timeout_seconds))

finish() {{
  local status="$1"
  local message="${{2:-}}"
  kill "${{qemu_pid}}" 2>/dev/null || true
  wait "${{qemu_pid}}" || true
  cat "${{log}}"
  if [[ -n "${{message}}" ]]; then
    echo "${{message}}" >&2
  fi
  exit "${{status}}"
}}

while kill -0 "${{qemu_pid}}" 2>/dev/null; do
  if grep -q "init: success" "${{log}}"; then
    finish 0
  fi
  if grep -Eq "init: failure|Kernel panic|RCU grace-period kthread stack dump|soft lockup" "${{log}}"; then
    finish 1
  fi
  if (( SECONDS >= deadline )); then
    finish 1 "timed out after ${{timeout_seconds}}s waiting for init: success"
  fi
  sleep 1
done

if grep -q "init: success" "${{log}}"; then
  finish 0
fi
finish 1
""".format(
            initrd = _rootpath(initrd, ctx.workspace_name),
            kernel = _rootpath(kernel, ctx.workspace_name),
            kernel_args = guest.kernel_args,
            name = ctx.label.name,
            qemu = _rootpath(qemu.qemu_system, ctx.workspace_name),
            qemu_args = " ".join(qemu_args),
            qemu_data_dir = _rootpath(qemu.system_data_anchor, ctx.workspace_name),
        ),
    )

    runfiles = ctx.runfiles(files = [
        qemu.qemu_system,
        qemu.system_data_anchor,
        kernel,
        initrd,
    ], transitive_files = qemu.system_data_files)
    return [DefaultInfo(executable = script, runfiles = runfiles)]

_aya_qemu_vm_test = rule(
    implementation = _aya_qemu_vm_test_impl,
    attrs = {
        "kernel": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "initrd": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "qemu_system_target": attr.string(
            mandatory = True,
            values = ["aarch64", "x86_64"],
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    cfg = _target_arch_transition,
    test = True,
    toolchains = [_QEMU_SYSTEM_TOOLCHAIN_TYPE],
)

def aya_qemu_vm_test(name, initrd, kernel, qemu_system_target, **kwargs):
    """Declares a QEMU integration test for an Aya guest architecture.

    Args:
      name: Test target name.
      initrd: Initramfs target.
      kernel: Linux kernel target.
      qemu_system_target: QEMU architecture, either aarch64 or x86_64.
      **kwargs: Additional test rule attributes.
    """
    target_platform = _GUESTS[qemu_system_target].platform
    kernel_target = name + "_kernel"
    initrd_target = name + "_initrd"

    platform_transition_filegroup(
        name = kernel_target,
        srcs = [kernel],
        tags = ["manual"],
        target_platform = target_platform,
    )
    platform_transition_filegroup(
        name = initrd_target,
        srcs = [initrd],
        tags = ["manual"],
        target_platform = target_platform,
    )
    _aya_qemu_vm_test(
        name = name,
        initrd = initrd_target,
        kernel = kernel_target,
        qemu_system_target = qemu_system_target,
        **kwargs
    )
