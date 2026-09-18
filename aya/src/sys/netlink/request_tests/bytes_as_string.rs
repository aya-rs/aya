include!("support.rs");

fn check(name: &[u8]) {
    request::Bpf::new(42, name, 0);
}
