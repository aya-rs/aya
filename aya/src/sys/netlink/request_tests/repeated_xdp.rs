include!("support.rs");

fn check(body: aya_obj::generated::ifinfomsg) {
    request::Link::new(body)
        .xdp(request::Xdp::new(-1, 0))
        .xdp(request::Xdp::new(-1, 0));
}
