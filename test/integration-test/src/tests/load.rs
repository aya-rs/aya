use std::{
    convert::TryInto as _,
    fs::File,
    thread,
    time::{Duration, SystemTime},
};

use aya::{
    maps::Array,
    programs::{
        links::{FdLink, PinnedLink},
        loaded_links, loaded_programs, FlowDissector, KProbe, TracePoint, UProbe, Xdp, XdpFlags,
    },
    util::KernelVersion,
    Bpf,
};
use aya_obj::programs::XdpAttachType;

const MAX_RETRIES: usize = 100;
const RETRY_DURATION: Duration = Duration::from_millis(10);

#[test]
fn long_name() {
    let mut bpf = Bpf::load(crate::NAME_TEST).unwrap();
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

#[test]
fn multiple_btf_maps() {
    let mut bpf = Bpf::load(crate::MULTIMAP_BTF).unwrap();

    let map_1: Array<_, u64> = bpf.take_map("map_1").unwrap().try_into().unwrap();
    let map_2: Array<_, u64> = bpf.take_map("map_2").unwrap().try_into().unwrap();

    let prog: &mut UProbe = bpf.program_mut("bpf_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach(Some("trigger_bpf_program"), 0, "/proc/self/exe", None)
        .unwrap();

    trigger_bpf_program();

    let key = 0;
    let val_1 = map_1.get(&key, 0).unwrap();
    let val_2 = map_2.get(&key, 0).unwrap();

    assert_eq!(val_1, 24);
    assert_eq!(val_2, 42);
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_bpf_program() {
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
                .filter_map(|prog| prog.ok())
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
                .filter_map(|link| link.ok())
                .find_map(|link| (link.prog_id == prog_id).then_some(link.id))
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

#[test]
fn unload_xdp() {
    let mut bpf = Bpf::load(crate::TEST).unwrap();
    let prog: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    prog.load().unwrap();
    assert_loaded("pass");
    let link = prog.attach("lo", XdpFlags::default()).unwrap();
    {
        let _link_owned = prog.take_link(link).unwrap();
        prog.unload().unwrap();
        assert_loaded_and_linked("pass");
    };

    assert_unloaded("pass");
    prog.load().unwrap();

    assert_loaded("pass");
    prog.attach("lo", XdpFlags::default()).unwrap();

    assert_loaded("pass");
    prog.unload().unwrap();

    assert_unloaded("pass");
}

#[test]
fn test_loaded_at() {
    let mut bpf = Bpf::load(crate::TEST).unwrap();
    let prog: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();

    // SystemTime is not monotonic, which can cause this test to flake. We don't expect the clock
    // timestamp to continuously jump around, so we add some retries. If the test is ever correct,
    // we know that the value returned by loaded_at() was reasonable relative to SystemTime::now().
    let mut failures = Vec::new();
    for _ in 0..5 {
        let t1 = SystemTime::now();
        prog.load().unwrap();
        let t2 = SystemTime::now();
        let loaded_at = prog.info().unwrap().loaded_at();
        prog.unload().unwrap();
        let range = t1..t2;
        if range.contains(&loaded_at) {
            failures.clear();
            break;
        }
        failures.push(LoadedAtRange(loaded_at, range));
    }
    assert!(
        failures.is_empty(),
        "loaded_at was not in range: {failures:?}",
    );

    struct LoadedAtRange(SystemTime, std::ops::Range<SystemTime>);
    impl std::fmt::Debug for LoadedAtRange {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let Self(loaded_at, range) = self;
            write!(f, "{range:?}.contains({loaded_at:?})")
        }
    }
}

#[test]
fn unload_kprobe() {
    let mut bpf = Bpf::load(crate::TEST).unwrap();
    let prog: &mut KProbe = bpf.program_mut("test_kprobe").unwrap().try_into().unwrap();
    prog.load().unwrap();
    assert_loaded("test_kprobe");
    let link = prog.attach("try_to_wake_up", 0).unwrap();
    {
        let _link_owned = prog.take_link(link).unwrap();
        prog.unload().unwrap();
        assert_loaded_and_linked("test_kprobe");
    };

    assert_unloaded("test_kprobe");
    prog.load().unwrap();

    assert_loaded("test_kprobe");
    prog.attach("try_to_wake_up", 0).unwrap();

    assert_loaded("test_kprobe");
    prog.unload().unwrap();

    assert_unloaded("test_kprobe");
}

#[test]
fn basic_tracepoint() {
    let mut bpf = Bpf::load(crate::TEST).unwrap();
    let prog: &mut TracePoint = bpf
        .program_mut("test_tracepoint")
        .unwrap()
        .try_into()
        .unwrap();

    prog.load().unwrap();
    assert_loaded("test_tracepoint");
    let link = prog.attach("syscalls", "sys_enter_kill").unwrap();

    {
        let _link_owned = prog.take_link(link).unwrap();
        prog.unload().unwrap();
        assert_loaded_and_linked("test_tracepoint");
    };

    assert_unloaded("test_tracepoint");
    prog.load().unwrap();

    assert_loaded("test_tracepoint");
    prog.attach("syscalls", "sys_enter_kill").unwrap();

    assert_loaded("test_tracepoint");
    prog.unload().unwrap();

    assert_unloaded("test_tracepoint");
}

#[test]
fn basic_uprobe() {
    let mut bpf = Bpf::load(crate::TEST).unwrap();
    let prog: &mut UProbe = bpf.program_mut("test_uprobe").unwrap().try_into().unwrap();

    prog.load().unwrap();
    assert_loaded("test_uprobe");
    let link = prog
        .attach(Some("uprobe_function"), 0, "/proc/self/exe", None)
        .unwrap();

    {
        let _link_owned = prog.take_link(link).unwrap();
        prog.unload().unwrap();
        assert_loaded_and_linked("test_uprobe");
    };

    assert_unloaded("test_uprobe");
    prog.load().unwrap();

    assert_loaded("test_uprobe");
    prog.attach(Some("uprobe_function"), 0, "/proc/self/exe", None)
        .unwrap();

    assert_loaded("test_uprobe");
    prog.unload().unwrap();

    assert_unloaded("test_uprobe");
}

#[test]
fn basic_flow_dissector() {
    let mut bpf = Bpf::load(crate::TEST).unwrap();
    let prog: &mut FlowDissector = bpf.program_mut("test_flow").unwrap().try_into().unwrap();

    prog.load().unwrap();
    assert_loaded("test_flow");

    let net_ns = File::open("/proc/self/ns/net").unwrap();
    let link = prog.attach(net_ns.try_clone().unwrap()).unwrap();
    {
        let _link_owned = prog.take_link(link).unwrap();
        prog.unload().unwrap();
        assert_loaded_and_linked("test_flow");
    };

    assert_unloaded("test_flow");
    prog.load().unwrap();

    assert_loaded("test_flow");
    prog.attach(net_ns).unwrap();

    assert_loaded("test_flow");
    prog.unload().unwrap();

    assert_unloaded("test_flow");
}

#[test]
fn pin_link() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 9, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, XDP uses netlink");
        return;
    }

    let mut bpf = Bpf::load(crate::TEST).unwrap();
    let prog: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let link_id = prog.attach("lo", XdpFlags::default()).unwrap();
    let link = prog.take_link(link_id).unwrap();
    assert_loaded("pass");

    let fd_link: FdLink = link.try_into().unwrap();
    let pinned = fd_link.pin("/sys/fs/bpf/aya-xdp-test-lo").unwrap();

    // because of the pin, the program is still attached
    prog.unload().unwrap();
    assert_loaded("pass");

    // delete the pin, but the program is still attached
    let new_link = pinned.unpin().unwrap();
    assert_loaded("pass");

    // finally when new_link is dropped we're detached
    drop(new_link);
    assert_unloaded("pass");
}

#[test]
fn pin_lifecycle() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 18, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, support for BPF_F_XDP_HAS_FRAGS was added in 5.18.0; see https://github.com/torvalds/linux/commit/c2f2cdb");
        return;
    }

    // 1. Load Program and Pin
    {
        let mut bpf = Bpf::load(crate::PASS).unwrap();
        let prog: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
        prog.load().unwrap();
        prog.pin("/sys/fs/bpf/aya-xdp-test-prog").unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded("pass");

    // 2. Load program from bpffs but don't attach it
    {
        let _ = Xdp::from_pin("/sys/fs/bpf/aya-xdp-test-prog", XdpAttachType::Interface).unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded("pass");

    // 3. Load program from bpffs and attach
    {
        let mut prog =
            Xdp::from_pin("/sys/fs/bpf/aya-xdp-test-prog", XdpAttachType::Interface).unwrap();
        let link_id = prog.attach("lo", XdpFlags::default()).unwrap();
        let link = prog.take_link(link_id).unwrap();
        let fd_link: FdLink = link.try_into().unwrap();
        fd_link.pin("/sys/fs/bpf/aya-xdp-test-lo").unwrap();

        // Unpin the program. It will stay attached since its links were pinned.
        prog.unpin().unwrap();
    }

    // should still be loaded since link was pinned
    assert_loaded_and_linked("pass");

    // 4. Load a new version of the program, unpin link, and atomically replace old program
    {
        let mut bpf = Bpf::load(crate::PASS).unwrap();
        let prog: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
        prog.load().unwrap();

        let link = PinnedLink::from_pin("/sys/fs/bpf/aya-xdp-test-lo")
            .unwrap()
            .unpin()
            .unwrap();
        prog.attach_to_link(link.try_into().unwrap()).unwrap();
        assert_loaded("pass");
    }

    // program should be unloaded
    assert_unloaded("pass");
}

#[test]
fn pin_lifecycle_tracepoint() {
    // 1. Load Program and Pin
    {
        let mut bpf = Bpf::load(crate::TEST).unwrap();
        let prog: &mut TracePoint = bpf
            .program_mut("test_tracepoint")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        prog.pin("/sys/fs/bpf/aya-tracepoint-test-prog").unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded("test_tracepoint");

    // 2. Load program from bpffs but don't attach it
    {
        let _ = TracePoint::from_pin("/sys/fs/bpf/aya-tracepoint-test-prog").unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded("test_tracepoint");

    // 3. Load program from bpffs and attach
    {
        let mut prog = TracePoint::from_pin("/sys/fs/bpf/aya-tracepoint-test-prog").unwrap();
        let link_id = prog.attach("syscalls", "sys_enter_kill").unwrap();
        let link = prog.take_link(link_id).unwrap();
        let fd_link: FdLink = link.try_into().unwrap();
        fd_link
            .pin("/sys/fs/bpf/aya-tracepoint-test-sys-enter-kill")
            .unwrap();

        // Unpin the program. It will stay attached since its links were pinned.
        prog.unpin().unwrap();
    }

    // should still be loaded since link was pinned
    assert_loaded_and_linked("test_tracepoint");

    // 4. unpin link, and make sure everything is unloaded
    {
        PinnedLink::from_pin("/sys/fs/bpf/aya-tracepoint-test-sys-enter-kill")
            .unwrap()
            .unpin()
            .unwrap();
    }

    // program should be unloaded
    assert_unloaded("test_tracepoint");
}

#[test]
fn pin_lifecycle_kprobe() {
    // 1. Load Program and Pin
    {
        let mut bpf = Bpf::load(crate::TEST).unwrap();
        let prog: &mut KProbe = bpf.program_mut("test_kprobe").unwrap().try_into().unwrap();
        prog.load().unwrap();
        prog.pin("/sys/fs/bpf/aya-kprobe-test-prog").unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded("test_kprobe");

    // 2. Load program from bpffs but don't attach it
    {
        let _ = KProbe::from_pin(
            "/sys/fs/bpf/aya-kprobe-test-prog",
            aya::programs::ProbeKind::KProbe,
        )
        .unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded("test_kprobe");

    // 3. Load program from bpffs and attach
    {
        let mut prog = KProbe::from_pin(
            "/sys/fs/bpf/aya-kprobe-test-prog",
            aya::programs::ProbeKind::KProbe,
        )
        .unwrap();
        let link_id = prog.attach("try_to_wake_up", 0).unwrap();
        let link = prog.take_link(link_id).unwrap();
        let fd_link: FdLink = link.try_into().unwrap();
        fd_link
            .pin("/sys/fs/bpf/aya-kprobe-test-try-to-wake-up")
            .unwrap();

        // Unpin the program. It will stay attached since its links were pinned.
        prog.unpin().unwrap();
    }

    // should still be loaded since link was pinned
    assert_loaded_and_linked("test_kprobe");

    // 4. unpin link, and make sure everything is unloaded
    {
        PinnedLink::from_pin("/sys/fs/bpf/aya-kprobe-test-try-to-wake-up")
            .unwrap()
            .unpin()
            .unwrap();
    }

    // program should be unloaded
    assert_unloaded("test_kprobe");
}

#[no_mangle]
#[inline(never)]
extern "C" fn uprobe_function() {
    core::hint::black_box(uprobe_function);
}

#[test]
fn pin_lifecycle_uprobe() {
    const FIRST_PIN_PATH: &str = "/sys/fs/bpf/aya-uprobe-test-prog-1";
    const SECOND_PIN_PATH: &str = "/sys/fs/bpf/aya-uprobe-test-prog-2";

    // 1. Load Program and Pin
    {
        let mut bpf = Bpf::load(crate::TEST).unwrap();
        let prog: &mut UProbe = bpf.program_mut("test_uprobe").unwrap().try_into().unwrap();
        prog.load().unwrap();
        prog.pin(FIRST_PIN_PATH).unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded("test_uprobe");

    // 2. Load program from bpffs but don't attach it
    {
        let _ = UProbe::from_pin(FIRST_PIN_PATH, aya::programs::ProbeKind::UProbe).unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded("test_uprobe");

    // 3. Load program from bpffs and attach
    {
        let mut prog = UProbe::from_pin(FIRST_PIN_PATH, aya::programs::ProbeKind::UProbe).unwrap();
        let link_id = prog
            .attach(Some("uprobe_function"), 0, "/proc/self/exe", None)
            .unwrap();
        let link = prog.take_link(link_id).unwrap();
        let fd_link: FdLink = link.try_into().unwrap();
        fd_link.pin(SECOND_PIN_PATH).unwrap();

        // Unpin the program. It will stay attached since its links were pinned.
        prog.unpin().unwrap();
    }

    // should still be loaded since link was pinned
    assert_loaded_and_linked("test_uprobe");

    // 4. unpin link, and make sure everything is unloaded
    {
        PinnedLink::from_pin(SECOND_PIN_PATH)
            .unwrap()
            .unpin()
            .unwrap();
    }

    // program should be unloaded
    assert_unloaded("test_uprobe");

    // Make sure the function isn't optimized out.
    uprobe_function();
}
