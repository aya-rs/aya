use std::fs;

/// Returns whether the running kernel is an Aya integration VM kernel built by Bazel.
pub(super) fn is_bazel_kernel() -> bool {
    // Both kernel fragments use CONFIG_LOCALVERSION="-aya-test" to identify
    // these kernels independently of their enabled features.
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap()
        .trim_end()
        .ends_with("-aya-test")
}
