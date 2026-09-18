include!("support.rs");

fn check(body: aya_obj::generated::tcmsg) {
    send_netlink!(
        Socket,
        request::RTM_NEWTFILTER,
        0,
        body,
        [attr(request::TCA_BPF_NAME, c"program"),]
    );
}
