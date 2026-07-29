use std::{
    os::fd::AsRawFd as _,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use assert_matches::assert_matches;
use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, MapData, MapType, ring_buf::RingBuf, user_ring_buf::UserRingBuf},
    programs::{UProbe, uprobe::UProbeScope},
    sys::is_map_supported,
};
use aya_obj::generated::BPF_RINGBUF_HDR_SZ;
use rand::RngExt as _;
use rstest::rstest;
use scopeguard::defer;
use tokio::io::{Interest, unix::AsyncFd};

// The producer ring buffer size. The loader rounds a ring buffer up to a power-of-2 multiple of the
// page size, so this must already be one for every page size CI runs on, otherwise CAPACITY would
// understate the real ring and the capacity-exact assertions would fail. 64 KiB satisfies that on
// 4 KiB, 16 KiB, and 64 KiB page kernels (16 * 4 KiB = 4 * 16 KiB = 1 * 64 KiB).
const BYTE_SIZE: u32 = 64 * 1024;

// The size, in bytes, that a published `u64` sample occupies in the ring (header plus payload,
// rounded up to 8). This is the kernel's per-sample stride.
const SAMPLE_SIZE: usize = (size_of::<u64>() + BPF_RINGBUF_HDR_SZ as usize).next_multiple_of(8);

// The number of `u64` samples the ring can hold at once.
const CAPACITY: usize = BYTE_SIZE as usize / SAMPLE_SIZE;

// The most samples any test echoes through RESULT before reading them back. The async no-drop test
// publishes this many, several times the producer ring capacity, so the producer must wait for the
// drainer to free space repeatedly.
const MAX_ECHOED_SAMPLES: usize = 3 * CAPACITY;

// RESULT must hold every echoed sample at once: the drainer can fill it before the reader runs, and
// the eBPF echo silently drops samples once RESULT is full. Size it to the next power-of-2 byte
// count (the kernel requires that for ring buffers) that fits the largest echo batch.
const RESULT_BYTE_SIZE: u32 = (MAX_ECHOED_SAMPLES * SAMPLE_SIZE).next_power_of_two() as u32;

// The trigger function the drain programs are attached to. The integration tests run
// single-threaded and each test loads its own maps, so a single shared trigger cannot cross-drain
// another test's ring buffer.
const TRIGGER: &str = "user_ring_buf_trigger_ebpf_program";

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn user_ring_buf_trigger_ebpf_program() {
    core::hint::black_box(());
}

// The (map, program) pairs the asynchronous tests run against. They iterate the variants internally
// rather than via rstest cases, mirroring ring_buf's async tests.
const VARIANTS: &[(&str, &str)] = &[
    ("USER_RING_BUF_LEGACY", "user_ring_buf_test_legacy"),
    ("USER_RING_BUF", "user_ring_buf_test"),
];

// The number of samples the writability tests publish. Far larger than the ring capacity so the
// producer has to wait for the drainer to free space many times over.
const NUM_MESSAGES: u64 = 20_000;

// Drains the user ring buffer continuously from another thread by hammering the trigger function,
// the inverse of ring_buf's WriterThread. Each call fires the process-wide uprobe, draining the
// pending samples and freeing space for the producer.
struct DrainerThread {
    thread: thread::JoinHandle<()>,
    done: Arc<AtomicBool>,
}

impl DrainerThread {
    fn spawn() -> Self {
        let done = Arc::new(AtomicBool::new(false));
        Self {
            thread: {
                let done = Arc::clone(&done);
                thread::spawn(move || {
                    while !done.load(Ordering::Relaxed) {
                        user_ring_buf_trigger_ebpf_program();
                    }
                })
            },
            done,
        }
    }

    fn join(self) {
        let Self { thread, done } = self;
        done.store(true, Ordering::Relaxed);
        thread.join().unwrap();
    }
}

struct UserRingBufTest {
    bpf: Ebpf,
    result: RingBuf<MapData>,
    user_ring_buf: UserRingBuf<MapData>,
    drain_count: Array<MapData, u64>,
}

// Returns `false` and prints a skip notice when the running kernel lacks user ring buffer support.
fn user_ring_buf_supported() -> bool {
    if is_map_supported(MapType::UserRingBuf).unwrap() {
        return true;
    }
    eprintln!("skipping test - user ring buffer maps not supported");
    false
}

// Sizes both producer rings and the `RESULT` echo ring on the loader.
fn size_maps(loader: &mut EbpfLoader<'_>) {
    for map in ["USER_RING_BUF", "USER_RING_BUF_LEGACY"] {
        loader.map_max_entries(map, BYTE_SIZE);
    }
    loader.map_max_entries("RESULT", RESULT_BYTE_SIZE);
}

// Loads the user ring buffer object, takes `map` as the producer plus the `RESULT` echo ring buffer
// and the `DRAIN_COUNT` array, and attaches `prog` to the trigger. Returns `None` when the running
// kernel lacks user ring buffer support.
fn load(map: &str, prog: &str) -> Option<UserRingBufTest> {
    load_with_mutators(map, prog, |_loader| {}, |_bpf| {})
}

// Like [`load`], but lets a test mutate the `EbpfLoader` before the object is loaded from disk (for
// example to set a pin path) and the loaded `Ebpf` before its program is attached (for example to
// pin a map), mirroring ring_buf's `RingBufTest::new_with_mutators`.
fn load_with_mutators<'loader>(
    map: &'loader str,
    prog: &str,
    loader_fn: impl FnOnce(&mut EbpfLoader<'loader>),
    bpf_fn: impl FnOnce(&mut Ebpf),
) -> Option<UserRingBufTest> {
    if !user_ring_buf_supported() {
        return None;
    }

    let mut loader = EbpfLoader::new();
    size_maps(&mut loader);
    loader_fn(&mut loader);
    let mut bpf = loader.load(crate::USER_RING_BUF).unwrap();
    bpf_fn(&mut bpf);

    let result = RingBuf::try_from(bpf.take_map("RESULT").unwrap()).unwrap();
    let user_ring_buf = UserRingBuf::try_from(bpf.take_map(map).unwrap()).unwrap();
    let drain_count = Array::try_from(bpf.take_map("DRAIN_COUNT").unwrap()).unwrap();

    let prog: &mut UProbe = bpf.program_mut(prog).unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach(TRIGGER, "/proc/self/exe", UProbeScope::AllProcesses)
        .unwrap();

    Some(UserRingBufTest {
        bpf,
        result,
        user_ring_buf,
        drain_count,
    })
}

// Reserves a `u64` sample, writes `value` into it, and submits it.
fn submit(user_ring_buf: &mut UserRingBuf<MapData>, value: u64) {
    let mut entry = user_ring_buf.reserve(size_of::<u64>()).unwrap();
    entry.copy_from_slice(&value.to_ne_bytes());
    entry.submit();
}

// Drains `n` echoed `u64` values out of the result ring buffer, busy-waiting until they arrive.
fn collect(result: &mut RingBuf<MapData>, n: usize) -> Vec<u64> {
    let mut seen = Vec::with_capacity(n);
    while seen.len() < n {
        if let Some(read) = result.next() {
            let read: [u8; 8] = (*read).try_into().unwrap();
            seen.push(u64::from_ne_bytes(read));
        }
    }
    seen
}

// Returns the sample count reported by the last drain.
fn drained(drain_count: &Array<MapData, u64>) -> u64 {
    drain_count.get(&0, 0).unwrap()
}

#[rstest]
#[case::legacy("USER_RING_BUF_LEGACY", "user_ring_buf_test_legacy")]
#[case::btf("USER_RING_BUF", "user_ring_buf_test")]
#[test_attr(test_log::test)]
fn user_ring_buf(#[case] map: &str, #[case] prog: &str) {
    let Some(UserRingBufTest {
        bpf: _bpf,
        mut result,
        mut user_ring_buf,
        drain_count,
    }) = load(map, prog)
    else {
        return;
    };

    // An oversized reservation is rejected rather than overflowing.
    assert!(user_ring_buf.reserve(usize::MAX).is_none());

    // Publish a batch of samples, submitting even values and discarding odd ones, so the test
    // exercises both the submit and discard paths.
    let mut rng = rand::rng();
    let mut expected = Vec::new();
    for value in std::iter::repeat_with(|| rng.random::<u64>()).take(64) {
        let mut entry = user_ring_buf.reserve(size_of::<u64>()).unwrap();
        entry.copy_from_slice(&value.to_ne_bytes());
        if value.is_multiple_of(2) {
            entry.submit();
            expected.push(value);
        } else {
            entry.discard();
        }
    }

    user_ring_buf_trigger_ebpf_program();

    let seen = collect(&mut result, expected.len());
    assert_matches!(result.next(), None);
    assert_eq!(seen, expected);
    // The drain reports only the submitted samples; discarded ones are skipped by the kernel.
    assert_eq!(drained(&drain_count), expected.len() as u64);
}

#[rstest]
#[case::legacy("USER_RING_BUF_LEGACY", "user_ring_buf_test_legacy")]
#[case::btf("USER_RING_BUF", "user_ring_buf_test")]
#[test_attr(test_log::test)]
fn user_ring_buf_drop_discards(#[case] map: &str, #[case] prog: &str) {
    let Some(UserRingBufTest {
        bpf: _bpf,
        mut result,
        mut user_ring_buf,
        drain_count,
    }) = load(map, prog)
    else {
        return;
    };

    // Reserve an entry and drop it without submitting; the kernel must skip it.
    drop(user_ring_buf.reserve(size_of::<u64>()).unwrap());

    // Submit a sentinel after the dropped entry. Only the sentinel must reach the drain callback.
    let sentinel = rand::rng().random::<u64>();
    submit(&mut user_ring_buf, sentinel);

    user_ring_buf_trigger_ebpf_program();

    let seen = collect(&mut result, 1);
    assert_matches!(result.next(), None);
    assert_eq!(seen, [sentinel]);
    // Only the sentinel is drained; the dropped entry is discarded.
    assert_eq!(drained(&drain_count), 1);
}

#[rstest]
#[case::legacy("USER_RING_BUF_LEGACY", "user_ring_buf_test_break_legacy")]
#[case::btf("USER_RING_BUF", "user_ring_buf_test_break")]
#[test_attr(test_log::test)]
fn user_ring_buf_break(#[case] map: &str, #[case] prog: &str) {
    let Some(UserRingBufTest {
        bpf: _bpf,
        mut result,
        mut user_ring_buf,
        drain_count,
    }) = load(map, prog)
    else {
        return;
    };

    // Submit two samples; the callback breaks after echoing the first.
    let mut rng = rand::rng();
    let values: [u64; 2] = [rng.random(), rng.random()];
    for value in values {
        submit(&mut user_ring_buf, value);
    }

    user_ring_buf_trigger_ebpf_program();

    // Only the first sample is echoed; the second is left in the ring buffer.
    let seen = collect(&mut result, 1);
    assert_matches!(result.next(), None);
    assert_eq!(seen, [values[0]]);
    assert_eq!(drained(&drain_count), 1);
}

#[rstest]
#[case::legacy("USER_RING_BUF_LEGACY", "user_ring_buf_test_legacy")]
#[case::btf("USER_RING_BUF", "user_ring_buf_test")]
#[test_attr(test_log::test)]
fn user_ring_buf_full(#[case] map: &str, #[case] prog: &str) {
    let Some(UserRingBufTest {
        bpf: _bpf,
        mut result,
        mut user_ring_buf,
        drain_count,
    }) = load(map, prog)
    else {
        return;
    };

    // Fill the ring buffer until a reservation fails, exercising the full-ring back pressure path.
    let mut published = Vec::new();
    let mut value: u64 = 0;
    while let Some(mut entry) = user_ring_buf.reserve(size_of::<u64>()) {
        entry.copy_from_slice(&value.to_ne_bytes());
        entry.submit();
        published.push(value);
        value += 1;
    }
    assert_eq!(published.len(), CAPACITY);

    user_ring_buf_trigger_ebpf_program();

    let seen = collect(&mut result, published.len());
    assert_matches!(result.next(), None);
    assert_eq!(seen, published);
    assert_eq!(drained(&drain_count), CAPACITY as u64);

    // Draining freed the ring, so a reservation succeeds again.
    let sentinel = value;
    submit(&mut user_ring_buf, sentinel);
    user_ring_buf_trigger_ebpf_program();
    let seen = collect(&mut result, 1);
    assert_matches!(result.next(), None);
    assert_eq!(seen, [sentinel]);
}

#[rstest]
#[case::legacy("USER_RING_BUF_LEGACY", "user_ring_buf_test_legacy")]
#[case::btf("USER_RING_BUF", "user_ring_buf_test")]
#[test_attr(test_log::test)]
fn user_ring_buf_wrap(#[case] map: &str, #[case] prog: &str) {
    let Some(UserRingBufTest {
        bpf: _bpf,
        mut result,
        mut user_ring_buf,
        drain_count,
    }) = load(map, prog)
    else {
        return;
    };

    // Reserve and drain in rounds smaller than the capacity, so each round leaves room. Enough
    // rounds to push the producer position past twice the ring size, exercising the wrap of the
    // double-mapped data region.
    const PER_ROUND: usize = CAPACITY / 2;
    const ROUNDS: usize = 2 * CAPACITY / PER_ROUND + 1;

    let mut value = 0;
    for _ in 0..ROUNDS {
        let mut published = Vec::with_capacity(PER_ROUND);
        for _ in 0..PER_ROUND {
            submit(&mut user_ring_buf, value);
            published.push(value);
            value += 1;
        }

        user_ring_buf_trigger_ebpf_program();

        let seen = collect(&mut result, published.len());
        assert_matches!(result.next(), None);
        assert_eq!(seen, published);
        assert_eq!(drained(&drain_count), PER_ROUND as u64);
    }
}

#[rstest]
#[case::legacy("USER_RING_BUF_LEGACY", "user_ring_buf_test_legacy")]
#[case::btf("USER_RING_BUF", "user_ring_buf_test")]
#[test_attr(test_log::test)]
fn user_ring_buf_short_sample(#[case] map: &str, #[case] prog: &str) {
    let Some(UserRingBufTest {
        bpf: _bpf,
        mut result,
        mut user_ring_buf,
        drain_count,
    }) = load(map, prog)
    else {
        return;
    };

    // Publish a sample too short to read as a `u64`; the drain callback's read returns `None` and
    // skips it without echoing.
    let mut rng = rand::rng();
    let mut short = user_ring_buf.reserve(size_of::<u32>()).unwrap();
    short.copy_from_slice(&rng.random::<u32>().to_ne_bytes());
    short.submit();

    let sentinel = rng.random::<u64>();
    submit(&mut user_ring_buf, sentinel);

    user_ring_buf_trigger_ebpf_program();

    let seen = collect(&mut result, 1);
    assert_matches!(result.next(), None);
    assert_eq!(seen, [sentinel]);
    // Both samples are drained even though only the sentinel is echoed.
    assert_eq!(drained(&drain_count), 2);
}

#[rstest]
#[case::legacy("USER_RING_BUF_LEGACY", "user_ring_buf_test_legacy")]
#[case::btf("USER_RING_BUF", "user_ring_buf_test")]
#[test_attr(test_log::test)]
fn user_ring_buf_pinned(#[case] map: &str, #[case] prog: &str) {
    let pin_path =
        Path::new("/sys/fs/bpf/").join(format!("user_ring_buf_{}", rand::rng().random::<u64>()));

    let mut rng = rand::rng();
    let before: [u64; 2] = [rng.random(), rng.random()];
    let after: [u64; 2] = [rng.random(), rng.random()];

    // Publish two samples into a pinned producer ring without draining them, then drop the handle.
    {
        let Some(UserRingBufTest {
            mut user_ring_buf, ..
        }) = load_with_mutators(
            map,
            prog,
            |_loader| {},
            |bpf| {
                bpf.map_mut(map).unwrap().pin(&pin_path).unwrap();
            },
        )
        else {
            return;
        };
        for value in before {
            submit(&mut user_ring_buf, value);
        }
    }
    defer! { std::fs::remove_file(&pin_path).unwrap() }

    // Reopen the pinned ring, publish two more samples, then drain everything. The samples written
    // before the reopen must still be present and ordered ahead of the new ones, which only holds if
    // the producer position survived the reopen.
    let Some(UserRingBufTest {
        bpf: _bpf,
        mut result,
        mut user_ring_buf,
        ..
    }) = load_with_mutators(
        map,
        prog,
        |loader| {
            loader.map_pin_path(map, &pin_path);
        },
        |_bpf| {},
    )
    else {
        return;
    };

    for value in after {
        submit(&mut user_ring_buf, value);
    }

    user_ring_buf_trigger_ebpf_program();

    let expected: Vec<u64> = before.into_iter().chain(after).collect();
    let seen = collect(&mut result, expected.len());
    assert_matches!(result.next(), None);
    assert_eq!(seen, expected);
}

#[rstest]
#[case::legacy("USER_RING_BUF_LEGACY")]
#[case::btf("USER_RING_BUF")]
#[test_attr(test_log::test)]
fn user_ring_buf_pinned_reopen_keeps_size(#[case] map: &str) {
    if !user_ring_buf_supported() {
        return;
    }

    let pin_path = Path::new("/sys/fs/bpf/").join(format!(
        "user_ring_buf_reopen_{}",
        rand::rng().random::<u64>()
    ));

    // Pin a sized ring, then drop the handle.
    {
        let mut loader = EbpfLoader::new();
        size_maps(&mut loader);
        let mut bpf = loader.load(crate::USER_RING_BUF).unwrap();
        bpf.map_mut(map).unwrap().pin(&pin_path).unwrap();
    }
    defer! { std::fs::remove_file(&pin_path).unwrap() }

    // Reopen the pinned ring without setting its max_entries. The size must come from the kernel,
    // not the zero declared in the object, otherwise the mmap is empty and reserve fails. This is
    // why the reopen loader is built by hand rather than through `size_maps`: only the other,
    // non-pinned producer is sized.
    let mut loader = EbpfLoader::new();
    loader.map_pin_path(map, &pin_path);
    for other in ["USER_RING_BUF", "USER_RING_BUF_LEGACY"] {
        if other != map {
            loader.map_max_entries(other, BYTE_SIZE);
        }
    }
    loader.map_max_entries("RESULT", RESULT_BYTE_SIZE);
    let mut bpf = loader.load(crate::USER_RING_BUF).unwrap();

    let mut user_ring_buf = UserRingBuf::try_from(bpf.take_map(map).unwrap()).unwrap();
    assert!(user_ring_buf.reserve(size_of::<u64>()).is_some());
}

// The inverse of ring_buf_asyncfd_events: the producer waits for writability through an AsyncFd
// while a background thread drains the ring, and must publish every sample without hanging.
#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn user_ring_buf_asyncfd_writable() {
    for &(map, prog) in VARIANTS {
        let Some(UserRingBufTest {
            bpf: _bpf,
            result: _result,
            user_ring_buf,
            drain_count: _drain_count,
        }) = load(map, prog)
        else {
            return;
        };

        // RESULT is not consumed here; the drain only needs to free space for the producer.
        let mut async_fd = AsyncFd::with_interest(user_ring_buf, Interest::WRITABLE).unwrap();
        let drainer = DrainerThread::spawn();
        let mut written: u64 = 0;
        while written < NUM_MESSAGES {
            let mut guard = async_fd.writable_mut().await.unwrap();
            let user_ring_buf = guard.get_inner_mut();
            loop {
                let Some(mut entry) = user_ring_buf.reserve(size_of::<u64>()) else {
                    // The ring is full; clear readiness so the next wait blocks until the drainer
                    // frees space.
                    guard.clear_ready();
                    break;
                };
                entry.copy_from_slice(&written.to_ne_bytes());
                entry.submit();
                written += 1;
                if written >= NUM_MESSAGES {
                    break;
                }
            }
        }
        drainer.join();
    }
}

// The inverse of ring_buf_epoll_wakeup: an edge-triggered EPOLLOUT registration must wake the
// producer each time the drainer frees space, so a full ring does not stall the producer forever.
#[test_log::test]
fn user_ring_buf_epoll_writable() {
    for &(map, prog) in VARIANTS {
        let Some(UserRingBufTest {
            bpf: _bpf,
            result: _result,
            mut user_ring_buf,
            drain_count: _drain_count,
        }) = load(map, prog)
        else {
            return;
        };

        let epoll_fd = epoll::create(false).unwrap();
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            user_ring_buf.as_raw_fd(),
            // EPOLLET mirrors tokio's AsyncFd and verifies the producer is woken on the
            // not-writable to writable transition rather than relying on level-triggering.
            epoll::Event::new(epoll::Events::EPOLLOUT | epoll::Events::EPOLLET, 0),
        )
        .unwrap();
        let mut epoll_event_buf = [epoll::Event::new(epoll::Events::EPOLLOUT, 0); 1];
        let drainer = DrainerThread::spawn();
        let mut written: u64 = 0;
        while written < NUM_MESSAGES {
            while let Some(mut entry) = user_ring_buf.reserve(size_of::<u64>()) {
                entry.copy_from_slice(&written.to_ne_bytes());
                entry.submit();
                written += 1;
                if written >= NUM_MESSAGES {
                    break;
                }
            }
            if written < NUM_MESSAGES {
                epoll::wait(epoll_fd, -1, &mut epoll_event_buf).unwrap();
            }
        }
        drainer.join();
    }
}

// The inverse of ring_buf_async_no_drop: the producer publishes a sequence larger than the ring
// while the drained samples are read back from RESULT concurrently, so nothing is dropped or
// reordered.
#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn user_ring_buf_async_no_drop() {
    for &(map, prog) in VARIANTS {
        let Some(UserRingBufTest {
            bpf: _bpf,
            result,
            user_ring_buf,
            drain_count: _drain_count,
        }) = load(map, prog)
        else {
            return;
        };

        const N: u64 = MAX_ECHOED_SAMPLES as u64;

        let mut producer_fd = AsyncFd::with_interest(user_ring_buf, Interest::WRITABLE).unwrap();
        let mut result_fd = AsyncFd::with_interest(result, Interest::READABLE).unwrap();
        let drainer = DrainerThread::spawn();

        let producer = async {
            let mut value: u64 = 0;
            while value < N {
                let mut guard = producer_fd.writable_mut().await.unwrap();
                let user_ring_buf = guard.get_inner_mut();
                loop {
                    let Some(mut entry) = user_ring_buf.reserve(size_of::<u64>()) else {
                        guard.clear_ready();
                        break;
                    };
                    entry.copy_from_slice(&value.to_ne_bytes());
                    entry.submit();
                    value += 1;
                    if value >= N {
                        break;
                    }
                }
            }
        };

        let reader = async {
            let mut seen = Vec::with_capacity(N as usize);
            while (seen.len() as u64) < N {
                let mut guard = result_fd.readable_mut().await.unwrap();
                let result = guard.get_inner_mut();
                while let Some(read) = result.next() {
                    let read: [u8; 8] = (*read).try_into().unwrap();
                    seen.push(u64::from_ne_bytes(read));
                }
                guard.clear_ready();
            }
            seen
        };

        let ((), seen) = tokio::join!(producer, reader);
        drainer.join();

        let expected: Vec<u64> = (0..N).collect();
        assert_eq!(seen, expected);
    }
}
