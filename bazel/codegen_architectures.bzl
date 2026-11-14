"""The target ABIs used by Aya's maintained source bindings."""

# Keys name Aya's generated bindings in source paths and Bazel targets.
# Each tuple gives the Clang target triple passed to bindgen, then the keys
# for the glibc and Linux UAPI header archives in LLVM's respective indexes.
# MIPS and MIPS64, for example, share kernel headers but use different libc ABIs.
CODEGEN_ARCHITECTURES = {
    "aarch64": ("aarch64-unknown-linux-gnu", "aarch64-linux-gnu", "arm64"),
    "armv7": ("armv7-unknown-linux-gnu", "arm-linux-gnueabi", "arm"),
    "loongarch64": ("loongarch64-unknown-linux-gnu", "loongarch64-linux-gnu", "loongarch"),
    "mips": ("mips-unknown-linux-gnu", "mips-linux-gnueabihf", "mips"),
    "mips64": ("mips64-unknown-linux-gnuabi64", "mips64-linux-gnuabi64", "mips"),
    "powerpc64": ("powerpc64le-unknown-linux-gnu", "powerpc64le-linux-gnu", "powerpc"),
    "riscv64": ("riscv64-unknown-linux-gnu", "riscv64-linux-gnu", "riscv"),
    "s390x": ("s390x-unknown-linux-gnu", "s390x-linux-gnu", "s390"),
    "x86_64": ("x86_64-unknown-linux-gnu", "x86_64-linux-gnu", "x86"),
}
