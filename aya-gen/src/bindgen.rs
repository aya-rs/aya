use bindgen::{self, Builder, EnumVariation};

pub fn builder() -> Builder {
    let bindgen = bindgen::builder()
        .use_core()
        .ctypes_prefix("::aya_bpf_cty")
        .layout_tests(false)
        .clang_arg("-Wno-unknown-attributes")
        .default_enum_style(EnumVariation::Consts)
        .prepend_enum_name(false);

    bindgen
}
