"""The target ABIs used by Aya's maintained source bindings."""

# Keep the libc ABI aligned with the target passed to libclang. In particular,
# armv7 uses soft-float headers, MIPS is big-endian with hard float, and
# PowerPC is little-endian.
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
