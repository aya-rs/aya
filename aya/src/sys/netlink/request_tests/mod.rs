/// ```no_run,standalone_crate
/// # fn main() {}
/// include!("valid.rs");
/// ```
mod valid;

/// ```compile_fail,E0308
/// # fn main() {}
/// include!("bytes_as_string.rs");
/// ```
mod bytes_as_string;

/// ```compile_fail,E0599
/// # fn main() {}
/// include!("repeated_xdp.rs");
/// ```
mod repeated_xdp;

/// ```compile_fail,E0599
/// # fn main() {}
/// include!("repeated_expected_fd.rs");
/// ```
mod repeated_expected_fd;

/// ```compile_fail,E0599
/// # fn main() {}
/// include!("repeated_classid.rs");
/// ```
mod repeated_classid;
