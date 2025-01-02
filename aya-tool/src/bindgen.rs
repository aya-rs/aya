use bindgen::{Builder, EnumVariation};

fn common_builder() -> Builder {
    bindgen::builder()
        .use_core()
        .layout_tests(false)
        .generate_comments(false)
        .prepend_enum_name(false)
        .clang_macro_fallback()
}

pub fn user_builder() -> Builder {
    common_builder().default_enum_style(EnumVariation::Rust {
        non_exhaustive: false,
    })
}

pub fn bpf_builder() -> Builder {
    common_builder()
        .ctypes_prefix("::aya_ebpf::cty")
        .clang_arg("-Wno-unknown-attributes")
        .default_enum_style(EnumVariation::ModuleConsts)
}
