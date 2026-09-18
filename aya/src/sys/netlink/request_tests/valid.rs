include!("support.rs");

fn check(
    link: aya_obj::generated::ifinfomsg,
    tc: aya_obj::generated::tcmsg,
    classid: Option<&u32>,
) {
    send_netlink!(
        Socket,
        request::RTM_SETLINK,
        0,
        link,
        [nested_attr(
            request::IFLA_XDP,
            [
                attr(request::IFLA_XDP_FD, &-1),
                attr(request::IFLA_XDP_FLAGS, &0),
            ]
        ),]
    );
    send_netlink!(
        Socket,
        request::RTM_NEWTFILTER,
        0,
        tc,
        [
            nested_attr(
                request::TCA_OPTIONS,
                [
                    attr(request::TCA_BPF_NAME, c"program"),
                    attr(request::TCA_BPF_CLASSID, classid),
                ]
            ),
            attr(request::TCA_KIND, c"bpf"),
        ]
    );
}
