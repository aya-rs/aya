use aya::{
    EbpfLoader,
    maps::{MapType, ring_buf::RingBuf},
    programs::{
        UProbe,
        uprobe::{UProbeAttachPoint, UProbeScope},
    },
    sys::BpfHelper,
    util::KernelVersion,
};

#[test_log::test]
fn test_uprobe_cookie() {
    // Ring buffer sizes are rounded up to a page-sized power-of-two multiple when
    // the object is loaded. Using 512 here therefore yields a one-page ring
    // buffer on supported test systems, which is ample for the handful of `u64`
    // cookie records emitted by this test.
    const RING_BUF_BYTE_SIZE: u32 = 512;
    let missing = super::unsupported_map_names([(MapType::RingBuf, &["RING_BUF"][..])]);
    let Some(mut bpf) = super::map_load_or_expect_unsupported(
        EbpfLoader::new()
            .map_max_entries("RING_BUF", RING_BUF_BYTE_SIZE)
            .load(crate::UPROBE_COOKIE),
        &missing,
    ) else {
        return;
    };
    let ring_buf = bpf.take_map("RING_BUF").unwrap();
    let mut ring_buf = RingBuf::try_from(ring_buf).unwrap();
    let prog: &mut UProbe = bpf
        .program_mut("uprobe_cookie")
        .unwrap()
        .try_into()
        .unwrap();
    match prog.load() {
        Ok(()) => {}
        Err(error) => {
            assert!(
                KernelVersion::current().unwrap() < KernelVersion::new(5, 15, 0),
                "unexpected uprobe cookie load failure: {error}"
            );
            super::assert_unsupported_helper(error, BpfHelper::BPF_FUNC_get_attach_cookie);
            return;
        }
    }
    const PROG_A: &str = "uprobe_cookie_trigger_ebpf_program_a";
    const PROG_B: &str = "uprobe_cookie_trigger_ebpf_program_b";
    let attach = |prog: &mut UProbe, fn_name: &str, cookie| {
        prog.attach(
            [UProbeAttachPoint {
                location: fn_name.into(),
                cookie: Some(cookie),
            }],
            "/proc/self/exe",
            UProbeScope::AllProcesses,
        )
        .unwrap()
    };

    // Note that the arguments we pass to the functions are meaningless, but we
    // pass the value we expect to see in the ring buffer from the cookie for
    // readability.
    let a = attach(prog, PROG_A, 1);
    let _b = attach(prog, PROG_B, 2);
    uprobe_cookie_trigger_ebpf_program_a(1);
    uprobe_cookie_trigger_ebpf_program_b(2);
    uprobe_cookie_trigger_ebpf_program_a(1);
    prog.detach(a).unwrap();
    let _a = attach(prog, PROG_A, 3);
    uprobe_cookie_trigger_ebpf_program_a(3);
    const EXP: &[u64] = &[1, 2, 1, 3];

    let mut seen = Vec::new();
    while let Some(read) = ring_buf.next() {
        let read = read.as_ref();
        match read.try_into() {
            Ok(read) => seen.push(u64::from_ne_bytes(read)),
            Err(std::array::TryFromSliceError { .. }) => {
                panic!("invalid ring buffer data: {read:x?}")
            }
        }
    }
    assert_eq!(seen, EXP);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn uprobe_cookie_trigger_ebpf_program_a(arg: u64) {
    std::hint::black_box(arg);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn uprobe_cookie_trigger_ebpf_program_b(arg: u32) {
    std::hint::black_box(arg);
}
