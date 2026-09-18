include!("support.rs");

fn check(body: aya_obj::generated::tcmsg) {
    send_netlink!(Socket, request::RTM_SETLINK, 0, body, []);
}
