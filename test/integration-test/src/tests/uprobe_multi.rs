use std::path::Path;

use aya::{
    EbpfLoader,
    maps::ring_buf::RingBuf,
    programs::{
        ProgramError, UProbe,
        uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeError},
    },
    util::KernelVersion,
};

const PROG_A: &str = "uprobe_multi_trigger_program_a";
const PROG_B: &str = "uprobe_multi_trigger_program_b";
const PROG_NO_COOKIE: &str = "uprobe_multi_trigger_program_no_cookie";
const PROG_SYMBOL_INVALID: &str = "uprobe_multi_missing_symbol";

#[test_log::test]
fn test_uprobe_attach_multi() {
    if !aya::features().bpf_cookie() {
        eprintln!(
            "skipping test: bpf_get_attach_cookie is unsupported so the test program cannot load"
        );
        return;
    }
    const RING_BUF_BYTE_SIZE: u32 = 512; // arbitrary, but big enough

    let mut bpf = EbpfLoader::new()
        .map_max_entries("RING_BUF", RING_BUF_BYTE_SIZE)
        .load(crate::UPROBE_MULTI)
        .unwrap();
    let ring_buf = bpf.take_map("RING_BUF").unwrap();
    let mut ring_buf = RingBuf::try_from(ring_buf).unwrap();
    let prog: &mut UProbe = bpf.program_mut("uprobe_multi").unwrap().try_into().unwrap();
    prog.load().unwrap();

    const COOKIE_A: u64 = 0x11;
    const COOKIE_B: u64 = 0x22;

    let points = [
        UProbeAttachPoint {
            location: UProbeAttachLocation::Symbol(PROG_A),
            cookie: Some(COOKIE_A),
        },
        UProbeAttachPoint {
            location: UProbeAttachLocation::Symbol(PROG_B),
            cookie: Some(COOKIE_B),
        },
        UProbeAttachPoint {
            location: UProbeAttachLocation::Symbol(PROG_NO_COOKIE),
            cookie: None,
        },
    ];
    let attach_res = prog.attach(points, Path::new("/proc/self/exe"), None);
    let link_id = match attach_res {
        Ok(link) => link,
        Err(ProgramError::UProbeError(UProbeError::UProbeMultiNotSupported)) => {
            let kernel_version = KernelVersion::current().unwrap();
            let multi_min = KernelVersion::new(6, 6, 0);
            assert!(
                kernel_version < multi_min,
                "kernel {kernel_version:?} is >= 6.6 but returned UProbeMultiNotSupported"
            );
            return;
        }
        Err(err) => panic!("attach failed: {err:?}"),
    };

    // Drain any stale events emitted by other tests before we generate fresh ones.
    while ring_buf.next().is_some() {}

    uprobe_multi_trigger_program_a();
    uprobe_multi_trigger_program_b();
    uprobe_multi_trigger_program_no_cookie();
    uprobe_multi_trigger_program_a();

    prog.detach(link_id).unwrap();
    // Call again, expect no events because detach removed all active links.
    uprobe_multi_trigger_program_a();

    const EXP: &[u64] = &[COOKIE_A, COOKIE_B, 0, COOKIE_A];
    let mut seen = Vec::new();
    while let Some(record) = ring_buf.next() {
        let data = record.as_ref();
        match data.try_into() {
            Ok(bytes) => seen.push(u64::from_ne_bytes(bytes)),
            Err(std::array::TryFromSliceError { .. }) => {
                panic!("invalid ring buffer data: {data:x?}")
            }
        }
    }
    assert_eq!(seen, EXP);
}

#[test_log::test]
fn test_uprobe_single_program_supports_multiple_points() {
    if !aya::features().bpf_cookie() {
        eprintln!(
            "skipping test: bpf_get_attach_cookie is unsupported so the test program cannot load"
        );
        return;
    }
    const RING_BUF_BYTE_SIZE: u32 = 512; // arbitrary, but big enough

    // Load a legacy single-attach program and verify Aya manages multi-point
    // attachments on top of the single-point perf path.
    let mut bpf = EbpfLoader::new()
        .map_max_entries("RING_BUF", RING_BUF_BYTE_SIZE)
        .load(crate::UPROBE_COOKIE)
        .unwrap();
    let ring_buf = bpf.take_map("RING_BUF").unwrap();
    let mut ring_buf = RingBuf::try_from(ring_buf).unwrap();
    let prog: &mut UProbe = bpf
        .program_mut("uprobe_cookie")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    const COOKIE_A: u64 = 0x33;
    const COOKIE_B: u64 = 0x44;
    let points = [
        UProbeAttachPoint {
            location: UProbeAttachLocation::Symbol(PROG_A),
            cookie: Some(COOKIE_A),
        },
        UProbeAttachPoint {
            location: UProbeAttachLocation::Symbol(PROG_B),
            cookie: Some(COOKIE_B),
        },
    ];
    let link_id = prog
        .attach(points, Path::new("/proc/self/exe"), None)
        .expect("legacy single-mode multi-point attach should succeed");

    // Drain any stale events emitted by other tests before we generate fresh ones.
    while ring_buf.next().is_some() {}

    uprobe_multi_trigger_program_a();
    uprobe_multi_trigger_program_b();

    prog.detach(link_id).unwrap();
    // Call again, expect no events because detach removed all underlying links.
    uprobe_multi_trigger_program_a();

    let mut seen = Vec::new();
    while let Some(record) = ring_buf.next() {
        let data = record.as_ref();
        match data.try_into() {
            Ok(bytes) => seen.push(u64::from_ne_bytes(bytes)),
            Err(std::array::TryFromSliceError { .. }) => {
                panic!("invalid ring buffer data: {data:x?}")
            }
        }
    }
    assert_eq!(seen, vec![COOKIE_A, COOKIE_B]);
}

#[test_log::test]
fn test_uprobe_single_program_composite_link_drop_detaches_all_points() {
    if !aya::features().bpf_cookie() {
        eprintln!(
            "skipping test: bpf_get_attach_cookie is unsupported so the test program cannot load"
        );
        return;
    }
    const RING_BUF_BYTE_SIZE: u32 = 512; // arbitrary, but big enough

    let mut bpf = EbpfLoader::new()
        .map_max_entries("RING_BUF", RING_BUF_BYTE_SIZE)
        .load(crate::UPROBE_COOKIE)
        .unwrap();
    let ring_buf = bpf.take_map("RING_BUF").unwrap();
    let mut ring_buf = RingBuf::try_from(ring_buf).unwrap();
    let prog: &mut UProbe = bpf
        .program_mut("uprobe_cookie")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    const COOKIE_A: u64 = 0x55;
    const COOKIE_B: u64 = 0x66;
    let points = [
        UProbeAttachPoint {
            location: UProbeAttachLocation::Symbol(PROG_A),
            cookie: Some(COOKIE_A),
        },
        UProbeAttachPoint {
            location: UProbeAttachLocation::Symbol(PROG_B),
            cookie: Some(COOKIE_B),
        },
    ];
    let link_id = prog
        .attach(points, Path::new("/proc/self/exe"), None)
        .expect("legacy single-mode multi-point attach should succeed");

    // Drain any stale events emitted by other tests before we generate fresh ones.
    while ring_buf.next().is_some() {}

    uprobe_multi_trigger_program_a();
    uprobe_multi_trigger_program_b();

    let link = prog.take_link(link_id).unwrap();
    drop(link);

    // Call again, expect no events because dropping the managed composite link
    // must detach all underlying single-point links.
    uprobe_multi_trigger_program_a();
    uprobe_multi_trigger_program_b();

    let mut seen = Vec::new();
    while let Some(record) = ring_buf.next() {
        let data = record.as_ref();
        match data.try_into() {
            Ok(bytes) => seen.push(u64::from_ne_bytes(bytes)),
            Err(std::array::TryFromSliceError { .. }) => {
                panic!("invalid ring buffer data: {data:x?}")
            }
        }
    }
    assert_eq!(seen, vec![COOKIE_A, COOKIE_B]);
}

#[test_log::test]
fn test_uprobe_attach_multi_invalid_symbol() {
    if !aya::features().bpf_cookie() {
        eprintln!(
            "skipping test: bpf_get_attach_cookie is unsupported so the test program cannot load"
        );
        return;
    }
    let mut bpf = EbpfLoader::new()
        .map_max_entries("RING_BUF", 512)
        .load(crate::UPROBE_MULTI)
        .unwrap();
    let prog: &mut UProbe = bpf.program_mut("uprobe_multi").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let points = [PROG_A, PROG_SYMBOL_INVALID];

    let attach_res = prog.attach(points, Path::new("/proc/self/exe"), None);
    match attach_res {
        Err(ProgramError::UProbeError(UProbeError::SymbolError { symbol, .. })) => {
            assert_eq!(symbol, PROG_SYMBOL_INVALID);
        }
        Err(ProgramError::UProbeError(UProbeError::UProbeMultiNotSupported)) => {
            let kernel_version = KernelVersion::current().unwrap();
            // Multi-uprobe landed in Linux 6.6 (see BPF_TRACE_UPROBE_MULTI in
            // https://elixir.bootlin.com/linux/v6.6/source/include/uapi/linux/bpf.h#L1042).
            let multi_min = KernelVersion::new(6, 6, 0);
            assert!(
                kernel_version < multi_min,
                "kernel {kernel_version:?} is >= 6.6 but returned UProbeMultiNotSupported"
            );
        }
        Err(err) => panic!("unexpected error for invalid symbol: {err:?}"),
        Ok(link) => panic!("attach succeeded for invalid symbol: {link:?}"),
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn uprobe_multi_trigger_program_a() {
    std::hint::black_box(1u64);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn uprobe_multi_trigger_program_b() {
    // Deliberately make the body differ from program_a so link-time ICF
    // doesn't fold both symbols onto the same address.
    std::hint::black_box(2u64);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn uprobe_multi_trigger_program_no_cookie() {
    std::hint::black_box(());
}
