use anyhow::Context as _;
use aya::{
    include_bytes_aligned,
    maps::{array::Array, ring_buf::RingBuf},
    programs::UProbe,
    Bpf, BpfLoader, Btf,
};
use std::os::fd::AsRawFd as _;
use tokio::{
    io::unix::AsyncFd,
    time::{sleep, Duration},
};

#[test]
fn ring_buf() {
    let bytes = include_bytes_aligned!("../../../target/bpfel-unknown-none/release/ring_buf");
    // Add 1 because the capacity at any given time is actually one less than
    // you might think because the consumer_pos and producer_pos being equal
    // would mean that the buffer is empty.
    let ring_buf_max_entries = RING_BUF_MAX_ENTRIES + 1;
    BpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .set_max_entries("RING_BUF", ring_buf_max_entries)
        .load(bytes);
    let mut bpf = Bpf::load(bytes).unwrap();
    let ring_buf = bpf.take_map("RING_BUF").unwrap();
    let mut ring_buf = RingBuf::try_from(ring_buf).unwrap();
    let rejected = bpf.take_map("REJECTED").unwrap();
    let rejected = Array::<_, u32>::try_from(rejected).unwrap();
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

    // Read the data back out of the ring buffer, expect only the even numbers.
    let expected: Vec<u64> = data.iter().cloned().filter(|v| *v % 2 == 0).collect();
    let mut seen = Vec::<u64>::new();
    while seen.len() < expected.len() {
        if let Some(item) = ring_buf.next() {
            let item: [u8; 8] = (*item).try_into().unwrap();
            let arg = u64::from_ne_bytes(item);
            seen.push(arg);
        }
    }

    // Ensure that the data that was read matches what was passed, and the
    // rejected count was set properly.
    assert_eq!(seen, expected);
    let rejected: usize = rejected.get(&0, 0).unwrap().try_into().unwrap();
    let expected_rejected = data.len() - expected.len();
    assert_eq!(rejected, expected_rejected)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn ring_buf_trigger_ebpf_program(_arg: u64) {}

const RING_BUF_MAX_ENTRIES: u32 = 1024; // corresponds to probe ringbuf size config

/// Generate a variable length vector of u64s. The number of values is always small enough to fit
/// into the RING_BUF defined in the probe.
pub(crate) fn gen_data() -> Vec<u64> {
    const DATA_LEN_RANGE: core::ops::RangeInclusive<usize> = 1..=RING_BUF_MAX_ENTRIES as usize;
    use rand::Rng as _;
    let mut rng = rand::thread_rng();
    let n = rng.gen_range(DATA_LEN_RANGE);
    std::iter::repeat_with(|| rng.gen()).take(n).collect()
}

#[tokio::test]
async fn ring_buf_async() {
    let bytes = include_bytes_aligned!("../../../target/bpfel-unknown-none/release/ring_buf");
    BpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .set_max_entries("RING_BUF", RING_BUF_MAX_ENTRIES)
        .load(bytes);
    let mut bpf = Bpf::load(bytes).unwrap();
    let ring_buf = bpf.take_map("RING_BUF").unwrap();
    let mut ring_buf = RingBuf::try_from(ring_buf).unwrap();
    let rejected = bpf.take_map("REJECTED").unwrap();
    let rejected = Array::<_, u32>::try_from(rejected).unwrap();

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
    let data = &data;
    let writer = call_ring_buf_trigger_ebpf_program_over_time(data);

    // Construct an AsyncFd from the RingBuf in order to receive readiness notifications.
    let async_fd = AsyncFd::new(ring_buf.as_raw_fd()).unwrap();
    let expected: Vec<u64> = data.iter().cloned().filter(|v| *v % 2 == 0).collect();
    let expected_count = expected.len();
    let reader = async {
        let mut seen = Vec::with_capacity(expected_count);
        while seen.len() < expected_count {
            // Wait for readiness, then clear the bit before reading so that no notifications
            // are missed.
            let res = async_fd.readable().await.unwrap().clear_ready();
            while let Some(read) = ring_buf.next() {
                let read: [u8; 8] = (*read)
                    .try_into()
                    .context(format!("data: {:?}", (&*read).len()))
                    .unwrap();
                let arg = u64::from_ne_bytes(read);
                seen.push(arg);
            }
        }
        seen
    };
    let ((), seen) = futures::future::join(writer, reader).await;

    // Ensure that the data that was read matches what was passed.
    assert_eq!(&seen, &expected);
    let rejected: usize = rejected.get(&0, 0).unwrap().try_into().unwrap();
    let expected_rejected = data.len() - expected.len();
    assert_eq!(rejected, expected_rejected)
}

async fn call_ring_buf_trigger_ebpf_program_over_time(data: &[u64]) {
    use rand::Rng as _;
    let mut rng = rand::thread_rng();
    let mut random_duration = || {
        let micros = rng.gen_range(0..1_000);
        Duration::from_micros(micros)
    };
    for value in data {
        sleep(random_duration()).await;
        ring_buf_trigger_ebpf_program(*value);
    }
}
