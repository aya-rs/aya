include!("support.rs");

fn check(body: aya_obj::generated::tcmsg, name: &[u8]) {
    send_netlink!(
        Socket,
        request::RTM_NEWTFILTER,
        0,
        body,
        [nested_attr(
            request::TCA_OPTIONS,
            [attr(request::TCA_BPF_NAME, name),]
        ),]
    );
}
