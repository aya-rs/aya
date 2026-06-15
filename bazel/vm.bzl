"""Hermetic VM helpers for integration tests."""

_QEMU_SYSTEM_TOOLCHAIN_TYPE = "@rules_qemu//qemu:system_toolchain_type"

def _guest_platform(qemu_system_target):
    if qemu_system_target == "aarch64":
        return "@rules_rs//rs/platforms:aarch64-unknown-linux-musl"
    if qemu_system_target == "x86_64":
        return "@rules_rs//rs/platforms:x86_64-unknown-linux-musl"
    fail("unsupported QEMU system target: %s" % qemu_system_target)

def _guest_platform_transition_impl(_, attr):
    qemu_system_target = attr.qemu_system_target
    return {
        "//command_line_option:platforms": _guest_platform(qemu_system_target),
        "//bazel:bpf_target_arch": qemu_system_target,
    }

_guest_platform_transition = transition(
    implementation = _guest_platform_transition_impl,
    inputs = [],
    outputs = [
        "//command_line_option:platforms",
        "//bazel:bpf_target_arch",
    ],
)

def _single_file(files, attr_name):
    if len(files) != 1:
        fail("%s must contain exactly one file, got %d" % (attr_name, len(files)))
    return files[0]

def _kernel_image(files, attr_name):
    matches = [file for file in files if file.basename.endswith(".Image") or file.basename.endswith(".bzImage")]
    if len(matches) != 1:
        fail("%s must contain exactly one kernel image, got %d" % (attr_name, len(matches)))
    return matches[0]

def _qemu_system_transition_impl(_, attr):
    return {"//bazel:qemu_system_target": attr.qemu_system_target}

_qemu_system_transition = transition(
    implementation = _qemu_system_transition_impl,
    inputs = [],
    outputs = ["//bazel:qemu_system_target"],
)

def _runfile_path(file):
    short_path = file.short_path
    if short_path.startswith("../"):
        return short_path[3:]
    return short_path

def _bash_array(values):
    return " ".join(values)

def _qemu_cpu(target_arch):
    if target_arch == "aarch64":
        # Keep this explicit: QEMU "max" has broken aarch64 CI before.
        return "neoverse-n1"
    if target_arch == "x86_64":
        return "max"
    fail("unsupported QEMU target arch: %s" % target_arch)

def _qemu_kernel_args(target_arch):
    if target_arch == "aarch64":
        return "console=ttyAMA0 lsm=bpf panic=-1"
    if target_arch == "x86_64":
        return "console=ttyS0,115200n8 rdinit=/init lsm=bpf panic=-1"
    fail("unsupported QEMU target arch: %s" % target_arch)

def _qemu_smp(target_arch):
    if target_arch == "aarch64":
        return "2"
    if target_arch == "x86_64":
        return "1"
    fail("unsupported QEMU target arch: %s" % target_arch)

def _aya_qemu_vm_test_impl(ctx):
    kernel = _kernel_image(ctx.files.kernel, "kernel")
    initrd = _single_file(ctx.files.initrd, "initrd")
    qemu = ctx.toolchains[_QEMU_SYSTEM_TOOLCHAIN_TYPE]
    script = ctx.actions.declare_file(ctx.label.name + ".sh")

    qemu_args = [
        "-machine",
        qemu.machine,
        "-cpu",
        _qemu_cpu(qemu.target_arch),
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
        _qemu_smp(qemu.target_arch),
    ]

    ctx.actions.write(
        output = script,
        is_executable = True,
        content = """#!/usr/bin/env bash
# --- begin runfiles.bash initialization v3 ---
set -uo pipefail; set +e; f=bazel_tools/tools/bash/runfiles/runfiles.bash
source "${{RUNFILES_DIR:-/dev/null}}/$f" 2>/dev/null || \\
  source "$(grep -sm1 "^$f " "${{RUNFILES_MANIFEST_FILE:-/dev/null}}" | cut -f2- -d' ')" 2>/dev/null || \\
  source "$0.runfiles/$f" 2>/dev/null || \\
  source "$(grep -sm1 "^$f " "$0.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null || \\
  source "$(grep -sm1 "^$f " "$0.exe.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null || \\
  {{ echo >&2 "ERROR: cannot find $f"; exit 1; }}
f=; set -e
# --- end runfiles.bash initialization v3 ---
set -euo pipefail

runfile() {{
  rlocation "$1" || rlocation "${{AYA_WORKSPACE}}/$1"
}}

qemu="$(runfile "${{AYA_QEMU}}")"
qemu_data_dir="$(runfile "${{AYA_QEMU_DATA_DIR}}")"
kernel="$(runfile "${{AYA_KERNEL}}")"
initrd="$(runfile "${{AYA_INITRD}}")"

kernel_args="${{AYA_KERNEL_ARGS}}"
for arg in "$@"; do
  kernel_args="${{kernel_args}} init.arg=${{arg}}"
done

log="${{TEST_TMPDIR:-/tmp}}/{name}.qemu.log"
rm -f "${{log}}"

"${{qemu}}" {qemu_args} -L "${{qemu_data_dir}}" -append "${{kernel_args}}" -kernel "${{kernel}}" -initrd "${{initrd}}" >"${{log}}" 2>&1 &
qemu_pid="$!"
timeout_seconds="${{TEST_TIMEOUT:-{timeout_seconds}}}"
deadline=$((SECONDS + timeout_seconds))

while kill -0 "${{qemu_pid}}" 2>/dev/null; do
  if grep -q "init: success" "${{log}}"; then
    kill "${{qemu_pid}}" 2>/dev/null || true
    wait "${{qemu_pid}}" || true
    cat "${{log}}"
    exit 0
  fi
  if grep -Eq "init: failure|Kernel panic|end Kernel panic|RCU grace-period kthread stack dump|soft lockup" "${{log}}"; then
    kill "${{qemu_pid}}" 2>/dev/null || true
    wait "${{qemu_pid}}" || true
    cat "${{log}}"
    exit 1
  fi
  if (( SECONDS >= deadline )); then
    kill "${{qemu_pid}}" 2>/dev/null || true
    wait "${{qemu_pid}}" || true
    cat "${{log}}"
    echo "timed out after ${{timeout_seconds}}s waiting for init: success" >&2
    exit 1
  fi
  sleep 1
done

wait "${{qemu_pid}}" || true
cat "${{log}}"
grep -q "init: success" "${{log}}"
""".format(
            name = ctx.label.name,
            qemu_args = _bash_array(qemu_args),
            timeout_seconds = 300,
        ),
    )

    runfiles = ctx.runfiles(files = [
        qemu.qemu_system,
        qemu.system_data_anchor,
        kernel,
        initrd,
    ], transitive_files = qemu.system_data_files)
    runfiles = runfiles.merge(ctx.attr._runfiles[DefaultInfo].default_runfiles)
    return [
        DefaultInfo(executable = script, runfiles = runfiles),
        RunEnvironmentInfo(environment = {
            "AYA_INITRD": _runfile_path(initrd),
            "AYA_KERNEL": _runfile_path(kernel),
            "AYA_KERNEL_ARGS": _qemu_kernel_args(qemu.target_arch),
            "AYA_QEMU": _runfile_path(qemu.qemu_system),
            "AYA_QEMU_DATA_DIR": _runfile_path(qemu.system_data_anchor),
            "AYA_WORKSPACE": ctx.workspace_name,
        }),
    ]

aya_qemu_vm_test = rule(
    implementation = _aya_qemu_vm_test_impl,
    attrs = {
        "kernel": attr.label(
            allow_files = True,
            cfg = _guest_platform_transition,
            mandatory = True,
        ),
        "initrd": attr.label(
            allow_files = True,
            cfg = _guest_platform_transition,
            mandatory = True,
        ),
        "qemu_system_target": attr.string(
            mandatory = True,
            values = ["aarch64", "x86_64"],
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
        "_runfiles": attr.label(default = "@bazel_tools//tools/bash/runfiles"),
    },
    cfg = _qemu_system_transition,
    test = True,
    toolchains = [_QEMU_SYSTEM_TOOLCHAIN_TYPE],
)
