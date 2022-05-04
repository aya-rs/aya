use bindgen::{self, Builder, EnumVariation};

pub fn user_builder() -> Builder {
    bindgen::builder()
        .layout_tests(false)
        .generate_comments(false)
        .prepend_enum_name(false)
        .default_enum_style(EnumVariation::Rust {
            non_exhaustive: false,
        })
}

pub fn bpf_builder() -> Builder {
    bindgen::builder()
        .use_core()
        .ctypes_prefix("::aya_bpf::cty")
        .layout_tests(false)
        .generate_comments(false)
        .clang_arg("-Wno-unknown-attributes")
        .default_enum_style(EnumVariation::ModuleConsts)
        .prepend_enum_name(false)
        // NOTE(vadorovsky): It's a workaround for the upstream bindgen issue:
        // https://github.com/rust-lang/rust-bindgen/issues/2083
        // tl;dr: Rust nightly complains about #[repr(packed)] structs deriving
        // Debug without Copy.
        // It needs to be fixed properly upstream, but for now we have to
        // disable Debug derive here.
        .derive_debug(false)
}
