use std::{ffi::OsStr, fs, sync::mpsc::sync_channel, thread};

use assert_matches::assert_matches;
use aya::{
    EbpfLoader,
    maps::{Array, MapData},
    programs::{
        KProbe, KProbeError, ProbeKind, ProgramError, ProgramType,
        kprobe::{KProbeAttachLocation, KProbeAttachPoint},
    },
    sys::{BpfHelper, is_helper_supported},
};
use integration_common::kprobe::{
    COOKIE_NONE_INDEX, COOKIE_SET_INDEX, COOKIE_UNEXPECTED_INDEX, EXPECTED_COOKIE, HITS_INDEX,
};

const MISSING_FUNCTION: &str = "__aya_missing_kprobe_function";

fn bpf_cookie_supported() -> bool {
    is_helper_supported(ProgramType::KProbe, BpfHelper::BPF_FUNC_get_attach_cookie).unwrap()
}

#[test_log::test]
fn kprobe_triggers() {
    let target_tgid = std::process::id();
    let mut bpf = EbpfLoader::new()
        .override_global("TARGET_TGID", &target_tgid, true)
        .load(crate::KPROBE)
        .unwrap();

    let hits = Array::try_from(bpf.take_map("HITS").unwrap()).unwrap();

    let prog: &mut KProbe = bpf
        .program_mut("test_kprobe_trigger")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach(["try_to_wake_up"]).unwrap();

    let hits_before = read_hits(&hits);

    trigger_scheduler();

    let hits_after = read_hits(&hits);
    assert!(
        hits_after > hits_before,
        "expected kprobe hits to increase, before={hits_before}, after={hits_after}"
    );
}

#[test_log::test]
fn kprobe_multi_triggers() {
    // bpf_get_func_ip (Linux 5.15+) lets the fixture verify each cookie against
    // the function that triggered it. Native multi-kprobe requires Linux 5.18+,
    // so this check does not raise the minimum kernel version for this test.
    if !bpf_cookie_supported()
        || !is_helper_supported(ProgramType::KProbe, BpfHelper::BPF_FUNC_get_func_ip).unwrap()
    {
        eprintln!(
            "skipping test: required kprobe helpers are unsupported so the test program cannot load"
        );
        return;
    }

    let target_tgid = std::process::id();
    let cookie_set_function_ip = kernel_symbol_address("schedule");
    let cookie_none_function_ip = kernel_symbol_address("try_to_wake_up");
    let mut bpf = EbpfLoader::new()
        .override_global("TARGET_TGID", &target_tgid, true)
        .override_global("COOKIE_SET_FUNCTION_IP", &cookie_set_function_ip, true)
        .override_global("COOKIE_NONE_FUNCTION_IP", &cookie_none_function_ip, true)
        .load(crate::KPROBE)
        .unwrap();

    let cookie_hits = Array::try_from(bpf.take_map("COOKIE_HITS").unwrap()).unwrap();
    let prog: &mut KProbe = bpf
        .program_mut("test_kprobe_multi_trigger")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    assert_matches!(
        prog.attach([KProbeAttachLocation::with_offset("schedule", 0)]),
        Err(ProgramError::KProbeError(
            KProbeError::FunctionOffsetRequiresSingleMode
        ))
    );

    // The eBPF fixture validates each cookie against the current function IP,
    // so swapping these parallel kernel ABI entries makes the test fail.
    let points = [
        KProbeAttachPoint {
            location: KProbeAttachLocation::from("schedule"),
            cookie: Some(EXPECTED_COOKIE),
        },
        KProbeAttachPoint {
            location: KProbeAttachLocation::from("try_to_wake_up"),
            cookie: None,
        },
    ];
    let link_id = match prog.attach(points) {
        Ok(link_id) => link_id,
        Err(ProgramError::KProbeError(KProbeError::MultiLinkNotSupported)) => {
            eprintln!("skipping test: native multi-kprobe links are unavailable");
            return;
        }
        Err(error) => panic!("multi-kprobe attach failed: {error:?}"),
    };

    let hits_before = read_cookie_hits(&cookie_hits);
    trigger_scheduler();
    let hits_after = read_cookie_hits(&cookie_hits);
    assert_expected_cookie_hits(hits_before, hits_after);

    prog.detach(link_id).unwrap();
    let hits_detached = read_cookie_hits(&cookie_hits);
    trigger_scheduler();
    let hits_after_detach = read_cookie_hits(&cookie_hits);
    assert_eq!(
        hits_after_detach, hits_detached,
        "detaching a native multi-kprobe link must remove every attachment"
    );
}

#[test_log::test]
fn kprobe_unknown_program_falls_back_to_many_single_links() {
    if !bpf_cookie_supported() {
        eprintln!(
            "skipping test: bpf_get_attach_cookie is unsupported so the test program cannot load"
        );
        return;
    }

    let target_tgid = std::process::id();
    let mut bpf = EbpfLoader::new()
        .override_global("TARGET_TGID", &target_tgid, true)
        .load(crate::KPROBE)
        .unwrap();

    let cookie_hits = Array::try_from(bpf.take_map("COOKIE_HITS").unwrap()).unwrap();
    let info = {
        let prog: &mut KProbe = bpf
            .program_mut("test_kprobe_cookie_trigger")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        prog.info().unwrap()
    };

    // Handles reconstructed from program info do not know whether the original
    // section was `kprobe` or `kprobe.multi`, so attach must probe and fall back.
    let mut prog = unsafe {
        KProbe::from_program_info(info, "test_kprobe_cookie_trigger".into(), ProbeKind::Entry)
    }
    .unwrap();
    let points = [
        KProbeAttachPoint {
            location: KProbeAttachLocation::from("schedule"),
            cookie: Some(EXPECTED_COOKIE),
        },
        KProbeAttachPoint {
            location: KProbeAttachLocation::from("try_to_wake_up"),
            cookie: None,
        },
    ];
    let link_id = prog
        .attach(points)
        .expect("unknown-mode multi-point attach should fall back to single attach");

    let hits_before = read_cookie_hits(&cookie_hits);
    trigger_scheduler();
    let hits_attached = read_cookie_hits(&cookie_hits);
    assert_expected_cookie_hits(hits_before, hits_attached);

    prog.detach(link_id).unwrap();
    // Take the baseline after detach: the test thread itself can hit `schedule`
    // between the previous map read and the detach operation.
    let hits_detached = read_cookie_hits(&cookie_hits);
    trigger_scheduler();
    let hits_after_detach = read_cookie_hits(&cookie_hits);
    assert_eq!(
        hits_after_detach, hits_detached,
        "detaching the composite link must remove every per-point attachment"
    );

    // The first attach selected and remembered the legacy per-point mode. A
    // second attach verifies that the reconstructed handle remains reusable.
    let link_id = prog
        .attach(points)
        .expect("unknown-mode fallback should allow attaching again");
    let hits_before = read_cookie_hits(&cookie_hits);
    trigger_scheduler();
    let hits_after = read_cookie_hits(&cookie_hits);
    assert_expected_cookie_hits(hits_before, hits_after);
    prog.detach(link_id).unwrap();
}

#[test_log::test]
fn kprobe_single_program_accepts_mixed_locations() {
    if !bpf_cookie_supported() {
        eprintln!(
            "skipping test: bpf_get_attach_cookie is unsupported so the test program cannot load"
        );
        return;
    }

    let target_tgid = std::process::id();
    let mut bpf = EbpfLoader::new()
        .override_global("TARGET_TGID", &target_tgid, true)
        .load(crate::KPROBE)
        .unwrap();

    let cookie_hits = Array::try_from(bpf.take_map("COOKIE_HITS").unwrap()).unwrap();
    let prog: &mut KProbe = bpf
        .program_mut("test_kprobe_cookie_trigger")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let points = [
        KProbeAttachPoint {
            location: KProbeAttachLocation::from("schedule"),
            cookie: Some(EXPECTED_COOKIE),
        },
        KProbeAttachPoint {
            location: KProbeAttachLocation::with_offset("try_to_wake_up", 0),
            cookie: None,
        },
    ];
    let link_id = prog
        .attach(points)
        .expect("legacy kprobe programs should accept mixed locations");

    let hits_before = read_cookie_hits(&cookie_hits);
    trigger_scheduler();
    let hits_after = read_cookie_hits(&cookie_hits);
    assert_expected_cookie_hits(hits_before, hits_after);

    let link = prog.take_link(link_id).unwrap();
    drop(link);

    let hits_detached = read_cookie_hits(&cookie_hits);
    trigger_scheduler();
    let hits_after_detach = read_cookie_hits(&cookie_hits);
    assert_eq!(
        hits_after_detach, hits_detached,
        "dropping the composite link must remove every per-point attachment"
    );
}

#[test_log::test]
fn kprobe_single_partial_failure_rolls_back() {
    let target_tgid = std::process::id();
    let mut bpf = EbpfLoader::new()
        .override_global("TARGET_TGID", &target_tgid, true)
        .load(crate::KPROBE)
        .unwrap();

    let hits = Array::try_from(bpf.take_map("HITS").unwrap()).unwrap();
    let prog: &mut KProbe = bpf
        .program_mut("test_kprobe_trigger")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    assert_matches!(
        prog.attach(["schedule", MISSING_FUNCTION]),
        Err(ProgramError::KProbeError(KProbeError::LegacyPerfAttachPointError {
            index,
            function,
            offset,
            ..
        })) => {
            assert_eq!(index, 1);
            assert_eq!(function.as_os_str(), OsStr::new(MISSING_FUNCTION));
            assert_eq!(offset, 0);
        }
    );

    let hits_after_failure = read_hits(&hits);
    trigger_scheduler();
    let hits_after_trigger = read_hits(&hits);
    assert_eq!(
        hits_after_trigger, hits_after_failure,
        "a partial attach failure must detach the preceding successful points"
    );
}

fn trigger_scheduler() {
    let (tx, rx) = sync_channel::<()>(0);
    let worker = thread::spawn(move || {
        rx.recv().unwrap();
    });
    tx.send(()).unwrap();
    worker.join().unwrap();
}

fn read_hits(hits: &Array<MapData, u64>) -> u64 {
    hits.get(&HITS_INDEX, 0).unwrap()
}

fn read_cookie_hits(hits: &Array<MapData, u64>) -> [u64; 3] {
    std::array::from_fn(|index| hits.get(&(index as u32), 0).unwrap())
}

fn kernel_symbol_address(name: &str) -> u64 {
    fs::read_to_string("/proc/kallsyms")
        .unwrap()
        .lines()
        .find_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let address = fields.next()?;
            let _kind = fields.next()?;
            (fields.next()? == name).then(|| u64::from_str_radix(address, 16).unwrap())
        })
        .filter(|address| *address != 0)
        .unwrap_or_else(|| panic!("kernel symbol `{name}` has no visible address"))
}

fn assert_expected_cookie_hits(before: [u64; 3], after: [u64; 3]) {
    assert!(
        after[COOKIE_NONE_INDEX as usize] > before[COOKIE_NONE_INDEX as usize],
        "expected hits with no cookie to increase, before={before:?}, after={after:?}"
    );
    assert!(
        after[COOKIE_SET_INDEX as usize] > before[COOKIE_SET_INDEX as usize],
        "expected hits with the configured cookie to increase, before={before:?}, after={after:?}"
    );
    assert_eq!(
        after[COOKIE_UNEXPECTED_INDEX as usize], before[COOKIE_UNEXPECTED_INDEX as usize],
        "observed an unexpected cookie binding, before={before:?}, after={after:?}"
    );
}
