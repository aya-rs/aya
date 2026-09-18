// Rustdoc checks these cases separately; rust-analyzer loads the same files
// as modules so navigation and macro expansion work inside the tests.

/// ```no_run,standalone_crate
/// # fn main() {}
/// include!("valid.rs");
/// ```
mod valid;

/// ```compile_fail,E0308
/// # fn main() {}
/// include!("wrong_body.rs");
/// ```
mod wrong_body;

/// ```compile_fail,E0277
/// # fn main() {}
/// include!("wrong_integer_width.rs");
/// ```
mod wrong_integer_width;

/// ```compile_fail,E0277
/// # fn main() {}
/// include!("bytes_as_string.rs");
/// ```
mod bytes_as_string;

/// ```compile_fail,E0308
/// # fn main() {}
/// include!("wrong_attribute_family.rs");
/// ```
mod wrong_attribute_family;

/// ```compile_fail,E0308
/// # fn main() {}
/// include!("wrong_nested_parent.rs");
/// ```
mod wrong_nested_parent;
