use bindgen::{self, Builder, EnumVariation};

pub fn user_builder() -> Builder {
    let bindgen = bindgen::builder()
        .layout_tests(false)
        .prepend_enum_name(false)
        .default_enum_style(EnumVariation::Rust {
            non_exhaustive: false,
        });

    bindgen
}

pub fn bpf_builder() -> Builder {
    let bindgen = bindgen::builder()
        .use_core()
        .ctypes_prefix("::aya_bpf_cty")
        .layout_tests(false)
        .clang_arg("-Wno-unknown-attributes")
        .default_enum_style(EnumVariation::ModuleConsts)
        .prepend_enum_name(false);

    bindgen
}
