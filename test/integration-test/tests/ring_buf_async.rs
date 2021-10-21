use std::os::fd::AsRawFd as _;

use aya::maps::RingBuf;

mod ring_buf;
use aya::{include_bytes_aligned, programs::UProbe, Bpf};
use ring_buf::{gen_data, ring_buf_trigger_ebpf_program};
use tokio::{
    io::unix::AsyncFd,
    task::spawn,
    time::{sleep, Duration},
};

#[tokio::test]
async fn ring_buf_async() {
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
    let write_handle = spawn(call_ring_buf_trigger_ebpf_program_over_time(data.clone()));

    // Construct an AsyncFd from the RingBuf in order to receive readiness notifications.
    let async_fd = AsyncFd::new(ring_buf.as_raw_fd()).unwrap();
    let seen = {
        let mut seen = Vec::with_capacity(data.len());
        while seen.len() < data.len() {
            // Wait for readiness, then clear the bit before reading so that no notifications
            // are missed.
            async_fd.readable().await.unwrap().clear_ready();
            while let Some(data) = ring_buf.next() {
                let data: [u8; 8] = (*data).try_into().unwrap();
                let arg = u64::from_ne_bytes(data);
                seen.push(arg);
            }
        }
        seen
    };

    // Ensure that the data that was read matches what was passed.
    assert_eq!(seen, data);
    write_handle.await.unwrap();
}

async fn call_ring_buf_trigger_ebpf_program_over_time(data: Vec<u64>) {
    let random_duration = || {
        use rand::Rng as _;
        let mut rng = rand::thread_rng();
        let micros = rng.gen_range(0..1_000);
        Duration::from_micros(micros)
    };
    for value in data {
        sleep(random_duration()).await;
        ring_buf_trigger_ebpf_program(value);
    }
}
