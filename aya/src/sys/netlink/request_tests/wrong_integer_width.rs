include!("support.rs");

fn check(body: aya_obj::generated::ifinfomsg, flags: &u64) {
    send_netlink!(
        Socket,
        request::RTM_SETLINK,
        0,
        body,
        [nested_attr(
            request::IFLA_XDP,
            [attr(request::IFLA_XDP_FLAGS, flags),]
        ),]
    );
}
