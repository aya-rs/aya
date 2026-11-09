include!("support.rs");

fn check() {
    request::Bpf::new(42, c"program", 0)
        .classid(None)
        .classid(Some(42u32));
}
