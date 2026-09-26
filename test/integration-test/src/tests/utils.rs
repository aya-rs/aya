use std::env;

/// Whether native multi-kprobe coverage is required instead of allowing tests to skip.
///
/// Bazel VM test targets enable this requirement; local runs may opt in with the same option.
pub(super) fn kprobe_multi_required() -> bool {
    const ENV_VAR: &str = "AYA_TEST_REQUIRE_KPROBE_MULTI";
    match env::var_os(ENV_VAR) {
        None => false,
        Some(value) if value == "0" => false,
        Some(value) if value == "1" => true,
        Some(value) => panic!("{ENV_VAR} must be 0 or 1, got {value:?}"),
    }
}
