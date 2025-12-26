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

#[test_log::test]
fn test_uprobe_attach_multi() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 6, 0) {
        eprintln!(
            "skipping test on kernel {kernel_version:?}, uprobe_multi links were added in 6.6"
        );
        return;
    }
    const RING_BUF_BYTE_SIZE: u32 = 512;
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
    let link_id = match prog.attach(points, Path::new("/proc/self/exe"), None) {
        Ok(link) => link,
        Err(aya::programs::ProgramError::UProbeError(
            aya::programs::uprobe::UProbeError::UProbeMultiNotSupported,
        )) => {
            eprintln!("skipping test on kernel {kernel_version:?}, uprobe_multi not supported");
            return;
        }
        Err(err) => panic!("attach failed: {err:?}"),
    };

    // Drain any stale events emitted by other tests before we generate fresh ones.
    while ring_buf.next().is_some() {}

    uprobe_multi_trigger_program_a(1);
    uprobe_multi_trigger_program_b(2);
    uprobe_multi_trigger_program_no_cookie();
    uprobe_multi_trigger_program_a(3);

    prog.detach(link_id).unwrap();
    // Fire another probe to ensure detach removed all active links.
    uprobe_multi_trigger_program_a(3);

    const EXP: &[u64] = &[COOKIE_A, COOKIE_B, 0, COOKIE_A];
    let mut seen = Vec::new();
    while let Some(record) = ring_buf.next() {
        let data = record.as_ref();
        match data.try_into() {
            Ok(bytes) => seen.push(u64::from_le_bytes(bytes)),
            Err(std::array::TryFromSliceError { .. }) => {
                panic!("invalid ring buffer data: {data:x?}")
            }
        }
    }
    assert_eq!(seen, EXP);
}

#[test_log::test]
fn test_uprobe_attach_multi_rejects_non_multi_program() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 6, 0) {
        eprintln!(
            "skipping test on kernel {kernel_version:?}, uprobe_multi links were added in 6.6"
        );
        return;
    }

    // Load the single-attach `uprobe_cookie` program to ensure multi-point
    // attach rejects plain uprobes.
    let mut bpf = EbpfLoader::new()
        .map_max_entries("RING_BUF", 64)
        .load(crate::UPROBE_COOKIE)
        .unwrap();
    let prog: &mut UProbe = bpf
        .program_mut("uprobe_cookie")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let locations = [PROG_A, PROG_B];

    match prog.attach(locations, Path::new("/proc/self/exe"), None) {
        Err(ProgramError::UProbeError(aya::programs::uprobe::UProbeError::ProgramNotMulti)) => {}
        Err(ProgramError::UProbeError(
            aya::programs::uprobe::UProbeError::UProbeMultiNotSupported,
        )) => {
            eprintln!("skipping test on kernel {kernel_version:?}, uprobe_multi not supported");
            return;
        }
        Err(err) => panic!("attach returned unexpected error: {err:?}"),
        Ok(_) => panic!("attach succeeded for non-multi program"),
    }
}

#[test_log::test]
fn test_uprobe_attach_multi_invalid_symbol() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 6, 0) {
        eprintln!(
            "skipping test on kernel {kernel_version:?}, uprobe_multi links were added in 6.6"
        );
        return;
    }

    let mut bpf = EbpfLoader::new()
        .map_max_entries("RING_BUF", 512)
        .load(crate::UPROBE_MULTI)
        .unwrap();
    let prog: &mut UProbe = bpf.program_mut("uprobe_multi").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let points = [PROG_A, "uprobe_multi_missing_symbol"];

    match prog.attach(points, Path::new("/proc/self/exe"), None) {
        Err(ProgramError::UProbeError(UProbeError::SymbolError { symbol, .. })) => {
            assert_eq!(symbol, "uprobe_multi_missing_symbol");
        }
        Err(ProgramError::UProbeError(UProbeError::UProbeMultiNotSupported)) => {
            eprintln!("skipping test on kernel {kernel_version:?}, uprobe_multi not supported");
        }
        Err(err) => panic!("unexpected error for invalid symbol: {err:?}"),
        Ok(_) => panic!("attach succeeded with invalid symbol"),
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn uprobe_multi_trigger_program_a(arg: u64) {
    std::hint::black_box(arg);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn uprobe_multi_trigger_program_b(arg: u64) {
    // Deliberately make the body differ from program_a so link-time ICF
    // doesn't fold both symbols onto the same address.
    std::hint::black_box(arg + 2);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn uprobe_multi_trigger_program_no_cookie() {
    std::hint::black_box(());
}
