include!("support.rs");

fn check(
    link: aya_obj::generated::ifinfomsg,
    tc: aya_obj::generated::tcmsg,
    classid: Option<u32>,
) -> Result<(), NetlinkErrorInternal> {
    #[cfg(feature = "test-helpers")]
    request::Link::new(link).send(&NetlinkSocket, 0)?;
    request::Link::new(link)
        .xdp(request::Xdp::new(-1, 0))
        .send(&NetlinkSocket, 0)?;
    request::Link::new(link)
        .xdp(request::Xdp::new(-1, 0).expected_fd(Some(12)))
        .send(&NetlinkSocket, 0)?;
    request::Tc::new_filter(tc, request::Bpf::new(42, c"program", 0)).send(&NetlinkSocket, 0)?;
    let request =
        request::Tc::new_filter(tc, request::Bpf::new(42, c"program", 0).classid(classid));
    request.send(&NetlinkSocket, 0)
}
