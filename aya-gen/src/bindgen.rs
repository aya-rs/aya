use bindgen::{self, Builder, EnumVariation};

pub fn user_builder() -> Builder {
    let bindgen = bindgen::builder()
        .layout_tests(false)
        .default_enum_style(EnumVariation::ModuleConsts)
        .prepend_enum_name(false);

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
