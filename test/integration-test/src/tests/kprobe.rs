use std::{
    ffi::OsStr,
    fs,
    io::{Read as _, Write as _},
};

use assert_matches::assert_matches;
use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, MapData},
    programs::{
        KProbe, KProbeError, ProbeKind, ProgramError,
        kprobe::{KProbeAttachLocation, KProbeAttachPoint},
        links::Link as _,
    },
    sys::BpfHelper,
};
use integration_common::kprobe::{
    COOKIE_NONE_INDEX, COOKIE_SET_INDEX, COOKIE_UNEXPECTED_INDEX, EXPECTED_COOKIE, HITS_INDEX,
};

use super::kprobe_multi_required;

const MISSING_FUNCTION: &str = "__aya_missing_kprobe_function";

type CookieHits = [u64; 3];

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
    prog.attach(["vfs_read"]).unwrap();

    let hits_before = read_hits(&hits);

    trigger_read();

    let hits_after = read_hits(&hits);
    assert!(
        hits_after > hits_before,
        "expected kprobe hits to increase, before={hits_before}, after={hits_after}"
    );
}

#[test_log::test]
fn kprobe_preserves_cookies() {
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
    if let Err(error) = prog.load() {
        assert_unsupported_helper(error, &[BpfHelper::BPF_FUNC_get_attach_cookie]);
        return;
    }

    let hits_before = read_cookie_hits(&cookie_hits);
    for cookie in [None, Some(EXPECTED_COOKIE)] {
        // Keep the single-point path covered independently of batch attachment.
        let link_id = prog
            .attach([KProbeAttachPoint {
                location: KProbeAttachLocation::from("vfs_read"),
                cookie,
            }])
            .unwrap();
        trigger_read();
        prog.detach(link_id).unwrap();
    }
    let hits_after = read_cookie_hits(&cookie_hits);
    assert_expected_cookie_hits(hits_before, hits_after);

    // Keep per-point cookies covered for a batch with both location forms.
    let hits_before = read_cookie_hits(&cookie_hits);
    let link_id = prog
        .attach([
            KProbeAttachPoint {
                location: KProbeAttachLocation::from("vfs_read"),
                cookie: Some(EXPECTED_COOKIE),
            },
            KProbeAttachPoint {
                location: KProbeAttachLocation::with_offset("vfs_write", 0),
                cookie: None,
            },
        ])
        .unwrap();
    trigger_io();
    let hits_after = read_cookie_hits(&cookie_hits);
    assert_expected_cookie_hits(hits_before, hits_after);
    prog.detach(link_id).unwrap();
}

#[test_log::test]
fn kprobe_unknown_program_falls_back_to_many_single_links() {
    let target_tgid = std::process::id();
    let mut bpf = EbpfLoader::new()
        .override_global("TARGET_TGID", &target_tgid, true)
        .load(crate::KPROBE)
        .unwrap();

    let hits = Array::try_from(bpf.take_map("HITS").unwrap()).unwrap();
    let info = {
        let prog: &mut KProbe = bpf
            .program_mut("test_kprobe_trigger")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        prog.info().unwrap()
    };

    // Handles reconstructed from program info do not know whether the original
    // section was `kprobe` or `kprobe.multi`, so attach must probe and fall back.
    // SAFETY: `info` comes from the entry kprobe `test_kprobe_trigger` loaded above,
    // so both the KProbe type and ProbeKind::Entry match the original program.
    let mut prog =
        unsafe { KProbe::from_program_info(info, "test_kprobe_trigger".into(), ProbeKind::Entry) }
            .unwrap();
    let points = ["vfs_read", "vfs_write"];
    let link_id = prog
        .attach(points)
        .expect("unknown-mode multi-point attach should fall back to single attach");

    assert_io_hits(&hits, 1);

    prog.detach(link_id).unwrap();
    assert_io_hits(&hits, 0);

    // The first attach selected and remembered the legacy per-point mode. A
    // second attach verifies that the reconstructed handle remains reusable.
    let link_id = prog
        .attach(points)
        .expect("unknown-mode fallback should allow attaching again");
    assert_io_hits(&hits, 1);
    prog.detach(link_id).unwrap();
}

#[test_log::test]
fn kprobe_single_program_accepts_mixed_locations() {
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

    let points = [
        KProbeAttachLocation::from("vfs_read"),
        KProbeAttachLocation::with_offset("vfs_write", 0),
    ];
    let link_id = prog
        .attach(points)
        .expect("legacy kprobe programs should accept mixed locations");

    assert_io_hits(&hits, 1);

    let link = prog.take_link(link_id).unwrap();
    drop(link);

    assert_io_hits(&hits, 0);
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
        prog.attach(["vfs_read", MISSING_FUNCTION]),
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
    trigger_read();
    let hits_after_trigger = read_hits(&hits);
    assert_eq!(
        hits_after_trigger, hits_after_failure,
        "a partial attach failure must detach the preceding successful points"
    );
}

// Synchronous I/O guarantees the probe target runs before checking the counters.
fn trigger_read() {
    let mut file = fs::File::open("/dev/null").unwrap();
    assert_eq!(file.read(&mut [0]).unwrap(), 0);
}

fn trigger_io() {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    assert_eq!(file.read(&mut [0]).unwrap(), 0);
    assert_eq!(file.write(&[0]).unwrap(), 1);
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

// Exercise each attachment independently; a total count could hide a missing point.
fn assert_io_hits(hits: &Array<MapData, u64>, expected: u64) {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    let before = read_hits(hits);
    assert_eq!(file.read(&mut [0]).unwrap(), 0);
    let after_read = read_hits(hits);
    assert_eq!(after_read - before, expected, "vfs_read hits");
    assert_eq!(file.write(&[0]).unwrap(), 1);
    assert_eq!(read_hits(hits) - after_read, expected, "vfs_write hits");
}

fn assert_unsupported_helper(error: ProgramError, helpers: &[BpfHelper]) {
    // Native multi-kprobe support includes bpf_get_attach_cookie and bpf_get_func_ip,
    // so tests requiring it must not accept a missing-helper load failure.
    assert!(
        !kprobe_multi_required(),
        "required kprobe coverage failed to load: {error}"
    );
    assert_matches!(error, ProgramError::LoadError { io_error, verifier_log } => {
        assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL));
        let log = verifier_log.to_string();
        assert!(helpers.iter().any(|helper| {
            let id = *helper as u32;
            log.lines().any(|line| {
                (line.starts_with("invalid func ") || line.starts_with("unknown func "))
                    && line.ends_with(&format!("#{id}"))
            })
        }), "expected rejection of {helpers:?}, got: {log}");
    });
}
