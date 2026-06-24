"""Hermetic VM helpers for integration tests."""

_QEMU_SYSTEM_TOOLCHAIN_TYPE = "@rules_qemu//qemu:exec_toolchain_type"

# Keep the QEMU settings and result protocol synchronized with
# xtask/src/run.rs::run. Bazel cannot invoke that Cargo runner because this rule
# must execute the configured QEMU toolchain with the transitioned kernel and
# initramfs as declared runfiles.
_GUESTS = {
    "aarch64": struct(
        cpu = "neoverse-n1",  # QEMU "max" has broken aarch64 CI before.
        kernel_args = "console=ttyAMA0 lsm=bpf panic=-1",
        platform = "@rules_rs//rs/platforms:aarch64-unknown-linux-musl",
        smp = "2",
    ),
    "x86_64": struct(
        cpu = "max",
        # xtask/src/run.rs::run uses noapic after observed
        # "IO-APIC + timer doesn't work!" kernel panics.
        kernel_args = "console=ttyS0,115200n8 rdinit=/init lsm=bpf noapic panic=-1",
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

def _guest_platform_transition_impl(_, attr):
    return {
        "//command_line_option:platforms": [_GUESTS[attr.qemu_system_target].platform],
    }

_guest_platform_transition = transition(
    implementation = _guest_platform_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _rootpath(file, workspace_name):
    # Custom rules cannot expand $(rootpath). File.short_path supplies the
    # runfiles-relative path; ctx.runfiles below makes each file available.
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
        "hvf",
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
fifo="${{TEST_TMPDIR:-/tmp}}/{name}.qemu.fifo"
rm -f "${{fifo}}"
mkfifo "${{fifo}}"

"${{qemu}}" {qemu_args} -L "${{qemu_data_dir}}" -append "${{kernel_args}}" -kernel "${{kernel}}" -initrd "${{initrd}}" >"${{fifo}}" 2>&1 &
qemu_pid="$!"
timeout_seconds="${{TEST_TIMEOUT:-300}}"
deadline=$((SECONDS + timeout_seconds))
outcome=""
termination_reason=""
soft_lockups=0

cleanup() {{
  kill "${{qemu_pid}}" 2>/dev/null || true
  rm -f "${{fifo}}"
}}
trap cleanup EXIT

terminate() {{
  if [[ -z "${{termination_reason}}" ]]; then
    termination_reason="$1"
  fi
  kill "${{qemu_pid}}" 2>/dev/null || true
}}

exec 3<"${{fifo}}"
while true; do
  if IFS= read -r -t 1 line <&3; then
    line="${{line%$'\r'}}"
    printf '%s\n' "${{line}}"
    printf '%s\n' "${{line}}" >>"${{log}}"

    case "${{line}}" in
      "init: success"|"init: failure")
        current_outcome="${{line#init: }}"
        if [[ -n "${{outcome}}" ]]; then
          terminate "multiple exit status: previous=${{outcome}}, current=${{current_outcome}}"
        else
          outcome="${{current_outcome}}"
        fi
        ;;
      "init: "*)
        terminate "unexpected init output: ${{line#init: }}"
        ;;
    esac

    if [[ "${{line}}" == *"end Kernel panic"* ]]; then
      terminate "end Kernel panic detected"
    elif [[ "${{line}}" == *"rcu: RCU grace-period kthread stack dump:"* ]]; then
      terminate "rcu: RCU grace-period kthread stack dump: detected"
    elif [[ "${{line}}" == *"watchdog: BUG: soft lockup"* ]]; then
      soft_lockups=$((soft_lockups + 1))
      if (( soft_lockups > 1 )); then
        terminate "watchdog: BUG: soft lockup detected more than once"
      fi
    fi
    continue
  fi

  if ! kill -0 "${{qemu_pid}}" 2>/dev/null; then
    break
  fi
  if (( SECONDS >= deadline )); then
    terminate "timed out after ${{timeout_seconds}}s waiting for QEMU"
  fi
done
exec 3<&-

if wait "${{qemu_pid}}"; then
  qemu_status=0
else
  qemu_status="$?"
fi

if [[ -n "${{termination_reason}}" ]]; then
  echo "${{termination_reason}}" >&2
  exit 1
fi
if (( qemu_status != 0 )); then
  echo "QEMU failed with status ${{qemu_status}}" >&2
  exit 1
fi

case "${{outcome}}" in
  success)
    ;;
  failure)
    echo "VM binaries failed" >&2
    exit 1
    ;;
  "")
    echo "init did not exit" >&2
    exit 1
    ;;
esac
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
            cfg = _guest_platform_transition,
            mandatory = True,
        ),
        "initrd": attr.label(
            allow_single_file = True,
            cfg = _guest_platform_transition,
            mandatory = True,
        ),
        "qemu_system_target": attr.string(
            mandatory = True,
            values = ["aarch64", "x86_64"],
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
    _aya_qemu_vm_test(
        name = name,
        initrd = initrd,
        kernel = kernel,
        qemu_system_target = qemu_system_target,
        **kwargs
    )
