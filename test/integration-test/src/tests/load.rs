use std::{convert::TryInto as _, fs::remove_file, path::Path, thread, time::Duration};

use assert_matches::assert_matches;
use aya::{
    Ebpf,
    maps::{Array, RingBuf},
    pin::PinError,
    programs::{
        FlowDissector, KProbe, LinkOrder, ProbeKind, Program, ProgramError, SchedClassifier,
        TcAttachType, TracePoint, UProbe, Xdp, XdpFlags,
        flow_dissector::{FlowDissectorLink, FlowDissectorLinkId},
        kprobe::{KProbeLink, KProbeLinkId},
        links::{FdLink, LinkError, PinnedLink},
        loaded_links, loaded_programs,
        tc::TcAttachOptions,
        trace_point::{TracePointLink, TracePointLinkId},
        uprobe::{UProbeLink, UProbeLinkId},
        xdp::{XdpLink, XdpLinkId},
    },
    util::KernelVersion,
};
use aya_obj::programs::XdpAttachType;

const MAX_RETRIES: usize = 100;
pub(crate) const RETRY_DURATION: Duration = Duration::from_millis(10);

#[test_log::test]
fn long_name() {
    let mut bpf = Ebpf::load(crate::NAME_TEST).unwrap();
    let name_prog: &mut Xdp = bpf
        .program_mut("ihaveaverylongname")
        .unwrap()
        .try_into()
        .unwrap();
    name_prog.load().unwrap();
    name_prog.attach("lo", XdpFlags::default()).unwrap();

    // We used to be able to assert with bpftool that the program name was short.
    // It seem though that it now uses the name from the ELF symbol table instead.
    // Therefore, as long as we were able to load the program, this is good enough.
}

#[test_log::test]
fn memmove() {
    let mut bpf = Ebpf::load(crate::MEMMOVE_TEST).unwrap();
    let prog: &mut Xdp = bpf.program_mut("do_dnat").unwrap().try_into().unwrap();
    prog.load().unwrap();
}

#[test_log::test]
fn ringbuffer_btf_map() {
    let mut bpf = Ebpf::load(crate::RINGBUF_BTF).unwrap();
    let ring_buf = bpf.take_map("map").unwrap();
    let mut ring_buf = RingBuf::try_from(ring_buf).unwrap();

    let prog: &mut UProbe = bpf.program_mut("bpf_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();
    match prog {
        UProbe::Single(p) => p.attach("trigger_bpf_program", "/proc/self/exe", None),
        UProbe::Multi(_) => panic!("expected single-attach program"),
        UProbe::Unknown(_) => panic!("unexpected unknown uprobe mode for loaded program"),
    }
    .unwrap();

    trigger_bpf_program();

    let item = ring_buf.next().unwrap();
    let item: [u8; 4] = (*item).try_into().unwrap();
    let val = u32::from_ne_bytes(item);
    assert_eq!(val, 0xdeadbeef);
}

#[test_log::test]
fn multiple_btf_maps() {
    let mut bpf = Ebpf::load(crate::MULTIMAP_BTF).unwrap();

    let map_1: Array<_, u64> = bpf.take_map("map_1").unwrap().try_into().unwrap();
    let map_2: Array<_, u64> = bpf.take_map("map_2").unwrap().try_into().unwrap();
    let map_pin_by_name: Array<_, u64> =
        bpf.take_map("map_pin_by_name").unwrap().try_into().unwrap();

    let prog: &mut UProbe = bpf.program_mut("bpf_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();
    match prog {
        UProbe::Single(p) => p.attach("trigger_bpf_program", "/proc/self/exe", None),
        UProbe::Multi(_) => panic!("expected single-attach program"),
        UProbe::Unknown(_) => panic!("unexpected unknown uprobe mode for loaded program"),
    }
    .unwrap();

    trigger_bpf_program();

    let key = 0;
    let val_1 = map_1.get(&key, 0).unwrap();
    let val_2 = map_2.get(&key, 0).unwrap();
    let val_3 = map_pin_by_name.get(&key, 0).unwrap();

    assert_eq!(val_1, 24);
    assert_eq!(val_2, 42);
    assert_eq!(val_3, 44);
    let map_pin = Path::new("/sys/fs/bpf/map_pin_by_name");
    assert!(&map_pin.exists());

    remove_file(map_pin).unwrap();
}

#[test_log::test]
fn pin_lifecycle_multiple_btf_maps() {
    let mut bpf = Ebpf::load(crate::MULTIMAP_BTF).unwrap();

    // "map_pin_by_name" should already be pinned, unpin and pin again later
    let map_pin_by_name_path = Path::new("/sys/fs/bpf/map_pin_by_name");

    assert!(map_pin_by_name_path.exists());
    remove_file(map_pin_by_name_path).unwrap();

    // pin and unpin all maps before casting to explicit types
    for (i, (name, map)) in bpf.maps_mut().enumerate() {
        // Don't pin system maps or the map that's already pinned by name.
        if name.contains(".rodata") || name.contains(".bss") {
            continue;
        }
        let map_pin_path = &Path::new("/sys/fs/bpf/").join(i.to_string());

        map.pin(map_pin_path).unwrap();

        assert!(map_pin_path.exists());
        remove_file(map_pin_path).unwrap();
    }

    let map_1: Array<_, u64> = bpf.take_map("map_1").unwrap().try_into().unwrap();
    let map_2: Array<_, u64> = bpf.take_map("map_2").unwrap().try_into().unwrap();
    let map_pin_by_name: Array<_, u64> =
        bpf.take_map("map_pin_by_name").unwrap().try_into().unwrap();

    let prog: &mut UProbe = bpf.program_mut("bpf_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();
    match prog {
        UProbe::Single(p) => p.attach("trigger_bpf_program", "/proc/self/exe", None),
        UProbe::Multi(_) => panic!("expected single-attach program"),
        UProbe::Unknown(_) => panic!("unexpected unknown uprobe mode for loaded program"),
    }
    .unwrap();

    trigger_bpf_program();

    let key = 0;
    let val_1 = map_1.get(&key, 0).unwrap();
    let val_2 = map_2.get(&key, 0).unwrap();
    let val_3 = map_pin_by_name.get(&key, 0).unwrap();

    assert_eq!(val_1, 24);
    assert_eq!(val_2, 42);
    assert_eq!(val_3, 44);

    let map_1_pin_path = Path::new("/sys/fs/bpf/map_1");
    let map_2_pin_path = Path::new("/sys/fs/bpf/map_2");

    map_1.pin(map_1_pin_path).unwrap();
    map_2.pin(map_2_pin_path).unwrap();
    map_pin_by_name.pin(map_pin_by_name_path).unwrap();
    assert!(map_1_pin_path.exists());
    assert!(map_2_pin_path.exists());
    assert!(map_pin_by_name_path.exists());

    remove_file(map_1_pin_path).unwrap();
    remove_file(map_2_pin_path).unwrap();
    remove_file(map_pin_by_name_path).unwrap();
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_bpf_program() {
    core::hint::black_box(trigger_bpf_program);
}

fn poll_loaded_program_id(name: &str) -> impl Iterator<Item = Option<u32>> + '_ {
    std::iter::once(true)
        .chain(std::iter::repeat(false))
        .map(|first| {
            if !first {
                thread::sleep(RETRY_DURATION);
            }
            // Ignore race failures which can happen when the tests delete a
            // program in the middle of a `loaded_programs()` call.
            loaded_programs()
                .filter_map(Result::ok)
                .find_map(|prog| (prog.name() == name.as_bytes()).then(|| prog.id()))
        })
}

#[track_caller]
fn assert_loaded_and_linked(name: &str) {
    let (attempts_used, prog_id) = poll_loaded_program_id(name)
        .take(MAX_RETRIES)
        .enumerate()
        .find_map(|(i, id)| id.map(|id| (i, id)))
        .unwrap_or_else(|| panic!("{name} not loaded after {MAX_RETRIES}"));
    let poll_loaded_link_id = std::iter::once(true)
        .chain(std::iter::repeat(false))
        .map(|first| {
            if !first {
                thread::sleep(RETRY_DURATION);
            }
            // Ignore race failures which can happen when the tests delete a
            // program in the middle of a `loaded_programs()` call.
            loaded_links()
                .filter_map(Result::ok)
                .find_map(|link| (link.program_id() == prog_id).then_some(link.id()))
        });
    assert!(
        poll_loaded_link_id
            .take(MAX_RETRIES)
            .skip(attempts_used)
            .any(|id| id.is_some()),
        "{name} not linked after {MAX_RETRIES}"
    );
}

#[track_caller]
fn assert_loaded(name: &str) {
    assert!(
        poll_loaded_program_id(name)
            .take(MAX_RETRIES)
            .any(|id| id.is_some()),
        "{name} not loaded after {MAX_RETRIES}"
    )
}

#[track_caller]
fn assert_unloaded(name: &str) {
    assert!(
        poll_loaded_program_id(name)
            .take(MAX_RETRIES)
            .any(|id| id.is_none()),
        "{name} still loaded after {MAX_RETRIES}"
    )
}

trait UnloadProgramOps {
    type LinkId;
    type OwnedLink;

    fn load(&mut self) -> Result<(), ProgramError>;
    fn unload(&mut self) -> Result<(), ProgramError>;
    fn take_link(&mut self, id: Self::LinkId) -> Result<Self::OwnedLink, ProgramError>;
}

macro_rules! impl_unload_program_ops {
    ($program:ty, $link_id:ty, $link:ty) => {
        impl UnloadProgramOps for $program {
            type LinkId = $link_id;
            type OwnedLink = $link;

            fn load(&mut self) -> Result<(), ProgramError> {
                <$program>::load(self)
            }

            fn unload(&mut self) -> Result<(), ProgramError> {
                <$program>::unload(self)
            }

            fn take_link(&mut self, id: Self::LinkId) -> Result<Self::OwnedLink, ProgramError> {
                <$program>::take_link(self, id)
            }
        }
    };
}

impl_unload_program_ops!(Xdp, XdpLinkId, XdpLink);
impl_unload_program_ops!(KProbe, KProbeLinkId, KProbeLink);
impl_unload_program_ops!(TracePoint, TracePointLinkId, TracePointLink);
impl_unload_program_ops!(UProbe, UProbeLinkId, UProbeLink);
impl_unload_program_ops!(FlowDissector, FlowDissectorLinkId, FlowDissectorLink);

#[test_log::test]
fn unload_xdp() {
    type P = Xdp;

    let program_name = "pass";
    let attach = |prog: &mut P| prog.attach("lo", XdpFlags::default()).unwrap();
    run_unload_program_test(
        crate::TEST,
        program_name,
        attach,
        /* expect_fd_link: */
        true, // xdp fallback is automatic, minimum version unclear.
    );
}

fn run_unload_program_test<P>(
    bpf_image: &[u8],
    program_name: &str,
    attach: fn(&mut P) -> P::LinkId,
    expect_fd_link: bool,
) where
    P: UnloadProgramOps,
    P::OwnedLink: TryInto<FdLink, Error = LinkError>,
    for<'a> &'a mut Program: TryInto<&'a mut P, Error = ProgramError>,
{
    let mut bpf = Ebpf::load(bpf_image).unwrap();
    let prog: &mut P = bpf.program_mut(program_name).unwrap().try_into().unwrap();
    prog.load().unwrap();
    assert_loaded(program_name);
    let link = attach(prog);
    let owned_link: P::OwnedLink = prog.take_link(link).unwrap();
    match owned_link.try_into() {
        Ok(_fd_link) => {
            assert!(
                expect_fd_link,
                "{program_name}: unexpectedly obtained an fd-backed link",
            );
            prog.unload().unwrap();
            assert_loaded_and_linked(program_name);
        }
        Err(err) => {
            assert_matches!(err, LinkError::InvalidLink);
            assert!(
                !expect_fd_link,
                "{program_name}: expected to obtain an fd-backed link on this kernel"
            );
            prog.unload().unwrap();
        }
    }

    assert_unloaded(program_name);
    prog.load().unwrap();

    assert_loaded(program_name);
    attach(prog);

    assert_loaded(program_name);
    prog.unload().unwrap();

    assert_unloaded(program_name);
}

#[test_log::test]
fn unload_kprobe() {
    type P = KProbe;

    let program_name = "test_kprobe";
    let attach = |prog: &mut P| prog.attach("try_to_wake_up", 0).unwrap();
    run_unload_program_test(
        crate::TEST,
        program_name,
        attach,
        aya::features().bpf_perf_link(), // probe uses perf_attach.
    );
}

#[test_log::test]
fn basic_tracepoint() {
    type P = TracePoint;

    let program_name = "test_tracepoint";
    let attach = |prog: &mut P| prog.attach("syscalls", "sys_enter_kill").unwrap();
    run_unload_program_test(
        crate::TEST,
        program_name,
        attach,
        aya::features().bpf_perf_link(), // tracepoint uses perf_attach.
    );
}

#[test_log::test]
fn basic_uprobe() {
    type P = UProbe;

    let program_name = "test_uprobe";
    let attach = |prog: &mut P| {
        match prog {
            UProbe::Single(p) => p.attach("uprobe_function", "/proc/self/exe", None),
            UProbe::Multi(_) => panic!("expected single-attach program"),
            UProbe::Unknown(_) => {
                panic!("unexpected unknown uprobe mode for loaded program")
            }
        }
        .unwrap()
    };
    run_unload_program_test(
        crate::TEST,
        program_name,
        attach,
        aya::features().bpf_perf_link(), // probe uses perf_attach.
    );
}

#[test_log::test]
fn basic_flow_dissector() {
    type P = FlowDissector;

    let program_name = "test_flow";
    let attach = |prog: &mut P| {
        let net_ns = std::fs::File::open("/proc/self/ns/net").unwrap();
        prog.attach(net_ns).unwrap()
    };
    run_unload_program_test(
        crate::TEST,
        program_name,
        attach,
        KernelVersion::current().unwrap() >= KernelVersion::new(5, 7, 0), // See FlowDissector::attach.
    );
}

#[test_log::test]
fn pin_link() {
    type P = Xdp;

    let program_name = "pass";
    let attach = |prog: &mut P| prog.attach("lo", XdpFlags::default()).unwrap();

    let mut bpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut P = bpf.program_mut(program_name).unwrap().try_into().unwrap();
    prog.load().unwrap();
    let link_id = attach(prog);
    let link = prog.take_link(link_id).unwrap();
    assert_loaded(program_name);

    let fd_link: FdLink = link.try_into().unwrap();
    let pinned = fd_link.pin("/sys/fs/bpf/aya-xdp-test-lo").unwrap();

    // because of the pin, the program is still attached
    prog.unload().unwrap();
    assert_loaded(program_name);

    // delete the pin, but the program is still attached
    let new_link = pinned.unpin().unwrap();
    assert_loaded(program_name);

    // finally when new_link is dropped we're detached
    drop(new_link);
    assert_unloaded(program_name);
}

#[test_log::test]
fn pin_tcx_link() {
    // TCX links require kernel >= 6.6
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 6, 0) {
        eprintln!("skipping pin_tcx_link test on kernel {kernel_version:?}");
        return;
    }

    use crate::utils::NetNsGuard;
    let _netns = NetNsGuard::new();

    let program_name = "tcx_next";
    let pin_path = "/sys/fs/bpf/aya-tcx-test-lo";
    let mut bpf = Ebpf::load(crate::TCX).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut(program_name).unwrap().try_into().unwrap();
    prog.load().unwrap();

    let link_id = prog
        .attach_with_options(
            "lo",
            TcAttachType::Ingress,
            TcAttachOptions::TcxOrder(LinkOrder::default()),
        )
        .unwrap();
    let link = prog.take_link(link_id).unwrap();
    assert_loaded(program_name);

    let fd_link: FdLink = link.try_into().unwrap();
    fd_link.pin(pin_path).unwrap();

    // Because of the pin, the program is still attached
    prog.unload().unwrap();
    assert_loaded(program_name);

    // Load a new program and atomically replace the old one using attach_to_link
    let mut bpf = Ebpf::load(crate::TCX).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut(program_name).unwrap().try_into().unwrap();
    prog.load().unwrap();

    let old_link = PinnedLink::from_pin(pin_path).unwrap();
    let link = FdLink::from(old_link).try_into().unwrap();
    let _link_id = prog.attach_to_link(link).unwrap();

    assert_loaded(program_name);

    // Clean up: remove the stale pin file and drop the bpf instance (which drops the program and link)
    remove_file(pin_path).unwrap();
    drop(bpf);
    assert_unloaded(program_name);
}

trait PinProgramOps {
    fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<(), PinError>;
    fn unpin(&mut self) -> Result<(), std::io::Error>;
}

macro_rules! impl_pin_program_ops {
    ($program:ty) => {
        impl PinProgramOps for $program {
            fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<(), PinError> {
                <$program>::pin(self, path)
            }

            fn unpin(&mut self) -> Result<(), std::io::Error> {
                <$program>::unpin(self)
            }
        }
    };
}

impl_pin_program_ops!(Xdp);
impl_pin_program_ops!(KProbe);
impl_pin_program_ops!(TracePoint);
impl_pin_program_ops!(UProbe);

#[test_log::test]
fn pin_lifecycle() {
    type P = Xdp;

    let program_name = "pass";
    let attach = |prog: &mut P| prog.attach("lo", XdpFlags::default()).unwrap();
    let program_pin = "/sys/fs/bpf/aya-xdp-test-prog";
    let link_pin = "/sys/fs/bpf/aya-xdp-test-lo";
    let from_pin = |program_pin: &str| P::from_pin(program_pin, XdpAttachType::Interface).unwrap();

    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 18, 0) {
        eprintln!(
            "skipping test on kernel {kernel_version:?}, support for BPF_F_XDP_HAS_FRAGS was added in 5.18.0; see https://github.com/torvalds/linux/commit/c2f2cdb"
        );
        return;
    }
    run_pin_program_lifecycle_test(
        crate::PASS,
        program_name,
        program_pin,
        link_pin,
        from_pin,
        attach,
        Some(|prog: &mut P, pinned: FdLink| {
            prog.attach_to_link(pinned.try_into().unwrap()).unwrap()
        }),
        /* expect_fd_link: */
        true, // xdp fallback is automatic, minimum version unclear.
    );
}

#[expect(clippy::too_many_arguments, reason = "let's see you do better")]
fn run_pin_program_lifecycle_test<P>(
    bpf_image: &[u8],
    program_name: &str,
    program_pin: &str,
    link_pin: &str,
    from_pin: fn(&str) -> P,
    attach: fn(&mut P) -> P::LinkId,
    attach_to_link: Option<fn(&mut P, FdLink) -> P::LinkId>,
    expect_fd_link: bool,
) where
    P: UnloadProgramOps + PinProgramOps,
    P::OwnedLink: TryInto<FdLink, Error = LinkError>,
    for<'a> &'a mut Program: TryInto<&'a mut P, Error = ProgramError>,
{
    let mut prog = {
        // 1. Load Program and Pin
        let mut bpf = Ebpf::load(bpf_image).unwrap();
        let prog: &mut P = bpf.program_mut(program_name).unwrap().try_into().unwrap();
        prog.load().unwrap();
        prog.pin(program_pin).unwrap();

        // 2. Load program from bpffs but don't attach it
        let prog = from_pin(program_pin);
        scopeguard::guard(prog, |mut prog| prog.unpin().unwrap())
    };

    // should still be loaded since prog was pinned
    assert_loaded(program_name);

    // 3. Load program from bpffs and attach
    {
        let link_id = attach(&mut *prog);
        let link = prog.take_link(link_id).unwrap();
        match link.try_into() {
            Ok(fd_link) => {
                assert!(
                    expect_fd_link,
                    "{program_name}: unexpectedly obtained an fd-backed link when perf-link support is unavailable"
                );
                fd_link.pin(link_pin).unwrap();

                // Unpin the program. It will stay attached since its links were pinned.
                drop(prog);

                // should still be loaded since link was pinned
                assert_loaded_and_linked(program_name);

                // 4. Load a new version of the program, unpin link, and atomically replace old program
                {
                    let link = PinnedLink::from_pin(link_pin).unwrap().unpin().unwrap();
                    if let Some(attach_to_link) = attach_to_link {
                        let mut bpf = Ebpf::load(bpf_image).unwrap();
                        let prog: &mut P =
                            bpf.program_mut(program_name).unwrap().try_into().unwrap();
                        prog.load().unwrap();
                        attach_to_link(prog, link);
                        assert_loaded(program_name);
                    }
                }
            }
            Err(err) => {
                assert_matches!(err, LinkError::InvalidLink);
                assert!(
                    !expect_fd_link,
                    "{program_name}: expected an fd-backed link on this kernel"
                );

                // Unpin the program. It will be unloaded since its link was not pinned.
                drop(prog);
            }
        }
    }

    // program should be unloaded
    assert_unloaded(program_name);
}

#[test_log::test]
fn pin_lifecycle_tracepoint() {
    type P = TracePoint;

    let program_name = "test_tracepoint";
    let attach = |prog: &mut P| prog.attach("syscalls", "sys_enter_kill").unwrap();
    let program_pin = "/sys/fs/bpf/aya-tracepoint-test-prog";
    let link_pin = "/sys/fs/bpf/aya-tracepoint-test-sys-enter-kill";
    let from_pin = |program_pin: &str| P::from_pin(program_pin).unwrap();
    run_pin_program_lifecycle_test(
        crate::TEST,
        program_name,
        program_pin,
        link_pin,
        from_pin,
        attach,
        None,
        aya::features().bpf_perf_link(), // tracepoint uses perf_attach.
    );
}

#[test_log::test]
fn pin_lifecycle_kprobe() {
    type P = KProbe;

    let program_name = "test_kprobe";
    let attach = |prog: &mut P| prog.attach("try_to_wake_up", 0).unwrap();
    let program_pin = "/sys/fs/bpf/aya-kprobe-test-prog";
    let link_pin = "/sys/fs/bpf/aya-kprobe-test-try-to-wake-up";
    let from_pin = |program_pin: &str| P::from_pin(program_pin, ProbeKind::Entry).unwrap();
    run_pin_program_lifecycle_test(
        crate::TEST,
        program_name,
        program_pin,
        link_pin,
        from_pin,
        attach,
        None,
        aya::features().bpf_perf_link(), // probe uses perf_attach.
    );
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn uprobe_function() {
    core::hint::black_box(uprobe_function);
}

#[test_log::test]
fn pin_lifecycle_uprobe() {
    type P = UProbe;

    let program_name = "test_uprobe";
    let attach = |prog: &mut P| {
        match prog {
            UProbe::Single(p) => p.attach("uprobe_function", "/proc/self/exe", None),
            UProbe::Multi(_) => panic!("expected single-attach program"),
            UProbe::Unknown(_) => {
                panic!("unexpected unknown uprobe mode for loaded program")
            }
        }
        .unwrap()
    };
    let program_pin = "/sys/fs/bpf/aya-uprobe-test-prog";
    let link_pin = "/sys/fs/bpf/aya-uprobe-test-uprobe-function";
    let from_pin = |program_pin: &str| {
        let prog = P::from_pin(program_pin, ProbeKind::Entry).unwrap();
        match prog {
            UProbe::Unknown(p) => UProbe::Single(p.into_single()),
            p => p,
        }
    };
    run_pin_program_lifecycle_test(
        crate::TEST,
        program_name,
        program_pin,
        link_pin,
        from_pin,
        attach,
        None,
        aya::features().bpf_perf_link(), // probe uses perf_attach.
    );

    // Make sure the function isn't optimized out.
    uprobe_function();
}
