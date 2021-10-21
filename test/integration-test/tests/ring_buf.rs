use aya::{include_bytes_aligned, maps::ring_buf::RingBuf, programs::UProbe, Bpf};

#[test]
fn ring_buf() {
    let bytes = include_bytes_aligned!("../../../target/bpfel-unknown-none/release/ring_buf");
    let mut bpf = Bpf::load(bytes).unwrap();
    let ring_buf = bpf.take_map("RING_BUF").unwrap();
    let mut ring_buf = RingBuf::try_from(ring_buf).unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("ring_buf_test")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach(
        Some("ring_buf_trigger_ebpf_program"),
        0,
        "/proc/self/exe",
        None,
    )
    .unwrap();

    // Generate some random data.
    let data = gen_data();

    // Call the function that the uprobe is attached to with randomly generated data.
    for val in &data {
        ring_buf_trigger_ebpf_program(*val);
    }
    // Read the data back out of the ring buffer.
    let mut seen = Vec::<u64>::new();
    while seen.len() < data.len() {
        if let Some(item) = ring_buf.next() {
            let item: [u8; 8] = (*item).try_into().unwrap();
            let arg = u64::from_ne_bytes(item);
            seen.push(arg);
        }
    }
    // Ensure that the data that was read matches what was passed.
    assert_eq!(seen, data);
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn ring_buf_trigger_ebpf_program(_arg: u64) {}

/// Generate a variable length vector of u64s. The number of values is always small enough to fit
/// into the RING_BUF defined in the probe.
pub(crate) fn gen_data() -> Vec<u64> {
    const DATA_LEN_RANGE: core::ops::RangeInclusive<usize> = 1..=1024;
    use rand::Rng as _;
    let mut rng = rand::thread_rng();
    let n = rng.gen_range(DATA_LEN_RANGE);
    std::iter::repeat_with(|| rng.gen()).take(n).collect()
}
