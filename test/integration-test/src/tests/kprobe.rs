use std::{ffi::OsStr, sync::mpsc::sync_channel, thread};

use assert_matches::assert_matches;
use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, MapData},
    programs::{
        KProbe, KProbeError, ProbeKind, ProgramError, ProgramType,
        kprobe::{KProbeAttachLocation, KProbeAttachPoint},
        links::Link as _,
    },
    sys::{BpfHelper, is_helper_supported},
};
use integration_common::kprobe::{
    COOKIE_NONE_INDEX, COOKIE_SET_INDEX, COOKIE_UNEXPECTED_INDEX, EXPECTED_COOKIE, HITS_INDEX,
};

use super::utils::kprobe_multi_required;

const MISSING_FUNCTION: &str = "__aya_missing_kprobe_function";

type CookieHits = [u64; 3];

fn kprobe_helper_supported(helper: BpfHelper) -> bool {
    let supported = is_helper_supported(ProgramType::KProbe, helper).unwrap();
    assert!(
        !kprobe_multi_required() || supported,
        "native multi-kprobe coverage requires kprobe helper {helper:?}"
    );
    supported
}

#[test_log::test]
fn tracefs_cleanup() {
    let mut bpf = Ebpf::load(crate::TEST).unwrap();
    let program: &mut KProbe = bpf.program_mut("test_kprobe").unwrap().try_into().unwrap();
    program.load().unwrap();
    super::check_tracefs_cleanup(
        "kprobe",
        1,
        || {
            let id = program.attach(["try_to_wake_up"]).unwrap();
            program.take_link(id).unwrap()
        },
        |link| link.detach().unwrap(),
    );
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
fn kprobe_single_point_preserves_cookie() {
    if !kprobe_helper_supported(BpfHelper::BPF_FUNC_get_attach_cookie) {
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

    let hits_before = read_cookie_hits(&cookie_hits);
    for cookie in [None, Some(EXPECTED_COOKIE)] {
        // Keep the single-point path covered independently of batch attachment.
        let link_id = prog
            .attach([KProbeAttachPoint {
                location: KProbeAttachLocation::from("try_to_wake_up"),
                cookie,
            }])
            .unwrap();
        trigger_scheduler();
        prog.detach(link_id).unwrap();
    }
    let hits_after = read_cookie_hits(&cookie_hits);
    assert_expected_cookie_hits(hits_before, hits_after);
}

#[test_log::test]
fn kprobe_unknown_program_falls_back_to_many_single_links() {
    if !kprobe_helper_supported(BpfHelper::BPF_FUNC_get_attach_cookie) {
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
    if !kprobe_helper_supported(BpfHelper::BPF_FUNC_get_attach_cookie) {
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

fn read_cookie_hits(hits: &Array<MapData, u64>) -> CookieHits {
    std::array::from_fn(|index| hits.get(&(index as u32), 0).unwrap())
}

fn assert_expected_cookie_hits(before: CookieHits, after: CookieHits) {
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
