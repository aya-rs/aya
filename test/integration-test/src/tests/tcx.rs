use std::{net::UdpSocket, time::Duration};

use assert_matches::assert_matches;
use aya::{
    Ebpf,
    maps::Array,
    programs::{
        LinkOrder, ProgramError, ProgramId, SchedClassifier, TcAttach, TcAttachType,
        tc::{NlOptions, qdisc_add_clsact},
    },
    test_helpers::NetNsGuard,
    util::KernelVersion,
};
use rstest::rstest;

#[rstest]
#[case::auto_ingress(TcAttach::Auto(TcAttachType::Ingress), Some(TcAttachType::Ingress))]
#[case::auto_egress(TcAttach::Auto(TcAttachType::Egress), Some(TcAttachType::Egress))]
#[case::netlink_ingress(TcAttach::Netlink {
    parent: TcAttachType::Ingress.into(),
    options: NlOptions::default(),
}, None)]
#[case::netlink_egress(TcAttach::Netlink {
    parent: TcAttachType::Egress.into(),
    options: NlOptions::default(),
}, None)]
#[test_attr(test_log::test)]
fn tc_attach(#[case] attach: TcAttach, #[case] expected_tcx: Option<TcAttachType>) {
    let _netns = NetNsGuard::new().unwrap();
    qdisc_add_clsact("lo").unwrap();

    let mut ebpf = Ebpf::load(crate::TCX).unwrap();
    let mut seen: Array<_, u32> = ebpf.take_map("SEEN").unwrap().try_into().unwrap();
    let prog: &mut SchedClassifier = ebpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let link = prog.attach("lo", attach).unwrap();
    if KernelVersion::current().unwrap() >= KernelVersion::new(6, 6, 0) {
        for query_type in [TcAttachType::Ingress, TcAttachType::Egress] {
            let expected_ids = if expected_tcx == Some(query_type) {
                vec![prog.info().unwrap().id()]
            } else {
                vec![]
            };
            let (_, programs) = SchedClassifier::query_tcx("lo", query_type).unwrap();
            assert_eq!(
                programs
                    .iter()
                    .map(aya::programs::ProgramInfo::id)
                    .collect::<Vec<_>>(),
                expected_ids
            );
        }
    }

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let round_trip = || {
        const PAYLOAD: &[u8] = b"hello tc";
        assert_eq!(socket.send_to(PAYLOAD, addr).unwrap(), PAYLOAD.len());
        let mut buf = [0; PAYLOAD.len() + 1];
        // Receiving the datagram ensures both TC hooks have finished before
        // inspecting the map, including when checking that detach took effect.
        let len = socket.recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], PAYLOAD);
    };

    round_trip();
    assert_eq!(seen.get(&0, 0).unwrap(), 1);

    prog.detach(link).unwrap();
    seen.set(0, &0, 0).unwrap();
    round_trip();
    assert_eq!(seen.get(&0, 0).unwrap(), 0);
}

#[test_log::test]
fn tcx_attach_does_not_fall_back_to_netlink() {
    let _netns = NetNsGuard::new().unwrap();
    // Install clsact so netlink can attach this program even while it has a
    // TCX link. An incorrect fallback would then turn the expected TCX error
    // into success, failing the assertion below.
    qdisc_add_clsact("lo").unwrap();

    let mut ebpf = Ebpf::load(crate::TCX).unwrap();
    let prog: &mut SchedClassifier = ebpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();

    if KernelVersion::current().unwrap() >= KernelVersion::new(6, 6, 0) {
        // TCX rejects duplicate program IDs on the same interface and hook.
        // `prog` retains the link even though we discard the returned ID, so
        // the second attach below exercises that rejection.
        prog.attach(
            "lo",
            TcAttach::Tcx(TcAttachType::Ingress, LinkOrder::default()),
        )
        .unwrap();
    }
    // Older kernels reject TCX itself. Both cases must return the TCX
    // syscall error for this explicit request.
    assert_matches!(
        prog.attach(
            "lo",
            TcAttach::Tcx(TcAttachType::Ingress, LinkOrder::default()),
        ),
        Err(ProgramError::SyscallError(_))
    );
}

#[test_log::test]
fn tcx_link_order() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 6, 0) {
        eprintln!("skipping tcx_link_order test on kernel {kernel_version:?}");
        return;
    }

    let _netns = NetNsGuard::new().unwrap();

    // We need a dedicated `Ebpf` instance for each program that we load
    // since TCX does not allow the same program ID to be attached multiple
    // times to the same interface/direction.
    //
    // Variables declared within this macro are within a closure scope to avoid
    // variable name conflicts.
    //
    // Yields a tuple of the `Ebpf` which must remain in scope for the duration
    // of the test, and the link ID of the attached program.
    macro_rules! attach_program_with_link_order_inner {
        ($program_name:ident, $link_order:expr) => {
            let mut ebpf = Ebpf::load(crate::TCX).unwrap();
            let $program_name: &mut SchedClassifier =
                ebpf.program_mut("tcx_next").unwrap().try_into().unwrap();
            $program_name.load().unwrap();
        };
    }
    macro_rules! attach_program_with_link_order {
        ($program_name:ident, $link_order:expr) => {
            attach_program_with_link_order_inner!($program_name, $link_order);
            $program_name
                .attach("lo", TcAttach::Tcx(TcAttachType::Ingress, $link_order))
                .unwrap();
        };
        ($program_name:ident, $link_id_name:ident, $link_order:expr) => {
            attach_program_with_link_order_inner!($program_name, $link_order);
            let $link_id_name = $program_name
                .attach("lo", TcAttach::Tcx(TcAttachType::Ingress, $link_order))
                .unwrap();
        };
    }

    attach_program_with_link_order!(default, LinkOrder::default());
    attach_program_with_link_order!(first, LinkOrder::first());
    attach_program_with_link_order!(last, last_link_id, LinkOrder::last());

    let last_link = last.take_link(last_link_id).unwrap();

    attach_program_with_link_order!(before_last, LinkOrder::before_link(&last_link).unwrap());
    attach_program_with_link_order!(after_last, LinkOrder::after_link(&last_link).unwrap());

    attach_program_with_link_order!(before_default, LinkOrder::before_program(default).unwrap());
    attach_program_with_link_order!(after_default, LinkOrder::after_program(default).unwrap());

    attach_program_with_link_order!(
        before_first,
        LinkOrder::before_program_id(unsafe { ProgramId::new(first.info().unwrap().id()) })
    );
    attach_program_with_link_order!(
        after_first,
        LinkOrder::after_program_id(unsafe { ProgramId::new(first.info().unwrap().id()) })
    );

    let expected_order = [
        before_first,
        first,
        after_first,
        before_default,
        default,
        after_default,
        before_last,
        last,
        after_last,
    ]
    .iter()
    .map(|program| program.info().unwrap().id())
    .collect::<Vec<_>>();

    let (revision, got_order) = SchedClassifier::query_tcx("lo", TcAttachType::Ingress).unwrap();
    assert_eq!(revision, (expected_order.len() + 1) as u64);
    assert_eq!(
        got_order
            .iter()
            .map(aya::programs::ProgramInfo::id)
            .collect::<Vec<_>>(),
        expected_order
    );
}
