use aya::{EbpfLoader, maps::ring_buf::RingBuf, programs::UProbe};
use test_log::test;

#[test]
fn test_uprobe_cookie() {
    const RING_BUF_BYTE_SIZE: u32 = 512; // arbitrary, but big enough

    let mut bpf = EbpfLoader::new()
        .set_max_entries("RING_BUF", RING_BUF_BYTE_SIZE)
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
    const PROG_A: &str = "uprobe_cookie_trigger_ebpf_program_a";
    const PROG_B: &str = "uprobe_cookie_trigger_ebpf_program_b";
    let attach = |prog: &mut UProbe, fn_name, cookie| {
        prog.attach(fn_name, "/proc/self/exe", None, Some(cookie))
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
            Ok(read) => seen.push(u64::from_le_bytes(read)),
            Err(std::array::TryFromSliceError { .. }) => {
                panic!("invalid ring buffer data: {read:x?}")
            }
        }
    }
    assert_eq!(seen, EXP);
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn uprobe_cookie_trigger_ebpf_program_a(arg: u64) {
    std::hint::black_box(arg);
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn uprobe_cookie_trigger_ebpf_program_b(arg: u32) {
    std::hint::black_box(arg);
}
