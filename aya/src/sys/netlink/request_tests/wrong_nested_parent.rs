include!("support.rs");

fn check(body: aya_obj::generated::tcmsg) {
    send_netlink!(
        Socket,
        request::RTM_NEWTFILTER,
        0,
        body,
        [nested_attr(
            request::IFLA_XDP,
            [attr(request::IFLA_XDP_FLAGS, &0),]
        ),]
    );
}
