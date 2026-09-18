include!("support.rs");

fn check() {
    request::Xdp::new(-1, 0)
        .expected_fd(None)
        .expected_fd(Some(12));
}
