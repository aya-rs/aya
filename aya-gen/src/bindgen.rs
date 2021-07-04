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
        .ctypes_prefix("::aya_bpf_cty")
        .layout_tests(false)
        .generate_comments(false)
        .clang_arg("-Wno-unknown-attributes")
        .default_enum_style(EnumVariation::ModuleConsts)
        .prepend_enum_name(false)
}
