use std::{
    fs, mem,
    os::fd::AsRawFd as _,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use anyhow::Context as _;
use assert_matches::assert_matches;
use aya::{
    Ebpf, EbpfLoader,
    maps::{Map, MapData, array::PerCpuArray, ring_buf::RingBuf},
    programs::UProbe,
};
use aya_obj::generated::BPF_RINGBUF_HDR_SZ;
use integration_common::ring_buf::Registers;
use rand::Rng as _;
use tokio::io::{Interest, unix::AsyncFd};

struct RingBufTest {
    _bpf: Ebpf,
    ring_buf: RingBuf<MapData>,
    regs: PerCpuArray<MapData, Registers>,
}

struct PinnedRingBufTest {
    _bpf: Ebpf,
    ring_buf: RingBuf<MapData>,
    regs: PerCpuArray<MapData, Registers>,
}

// Note that it is important for this test that RING_BUF_MAX_ENTRIES ends up creating a ring buffer
// that is exactly a power-of-two multiple of the page size. The synchronous test will fail if
// that's not the case because the actual size will be rounded up, and fewer entries will be dropped
// than expected.
const RING_BUF_MAX_ENTRIES: usize = 512;
const RING_BUF_PIN_PATH: &str = "/sys/fs/bpf/RING_BUF";

impl RingBufTest {
    fn new() -> Self {
        const RING_BUF_BYTE_SIZE: u32 =
            (RING_BUF_MAX_ENTRIES * (mem::size_of::<u64>() + BPF_RINGBUF_HDR_SZ as usize)) as u32;

        // Use the loader API to control the size of the ring_buf.
        let mut bpf = EbpfLoader::new()
            .set_max_entries("RING_BUF", RING_BUF_BYTE_SIZE)
            .load(crate::RING_BUF)
            .unwrap();
        let ring_buf = bpf.take_map("RING_BUF").unwrap();
        let ring_buf = RingBuf::try_from(ring_buf).unwrap();
        let regs = bpf.take_map("REGISTERS").unwrap();
        let regs = PerCpuArray::<_, Registers>::try_from(regs).unwrap();
        let prog: &mut UProbe = bpf
            .program_mut("ring_buf_test")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        prog.attach(
            "ring_buf_trigger_ebpf_program",
            "/proc/self/exe",
            None,
            None,
        )
        .unwrap();

        Self {
            _bpf: bpf,
            ring_buf,
            regs,
        }
    }
}

impl PinnedRingBufTest {
    fn new() -> Self {
        const RING_BUF_BYTE_SIZE: u32 =
            (RING_BUF_MAX_ENTRIES * (mem::size_of::<u64>() + BPF_RINGBUF_HDR_SZ as usize)) as u32;

        let mut bpf = EbpfLoader::new()
            .set_max_entries("RING_BUF", RING_BUF_BYTE_SIZE)
            .load(crate::RING_BUF_PINNED)
            .unwrap();
        // We assume the map has been pinned as part of the loading process
        let ring_buf = MapData::from_pin(RING_BUF_PIN_PATH).unwrap();
        let ring_buf = Map::RingBuf(ring_buf);
        let ring_buf = RingBuf::try_from(ring_buf).unwrap();
        let regs = bpf.take_map("REGISTERS").unwrap();
        let regs = PerCpuArray::<_, Registers>::try_from(regs).unwrap();
        let prog: &mut UProbe = bpf
            .program_mut("ring_buf_test")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        prog.attach(
            "ring_buf_trigger_ebpf_program",
            "/proc/self/exe",
            None,
            None,
        )
        .unwrap();

        Self {
            _bpf: bpf,
            ring_buf,
            regs,
        }
    }
}

struct WithData(RingBufTest, Vec<u64>);
struct PinnedWithData(PinnedRingBufTest, Vec<u64>);

impl WithData {
    fn new(n: usize) -> Self {
        Self(RingBufTest::new(), {
            let mut rng = rand::rng();
            std::iter::repeat_with(|| rng.random()).take(n).collect()
        })
    }
}

impl PinnedWithData {
    fn new(n: usize) -> Self {
        Self(PinnedRingBufTest::new(), {
            let mut rng = rand::rng();
            std::iter::repeat_with(|| rng.random()).take(n).collect()
        })
    }
}

#[test_case::test_case(0; "write zero items")]
#[test_case::test_case(1; "write one item")]
#[test_case::test_case(RING_BUF_MAX_ENTRIES / 2; "write half the capacity items")]
#[test_case::test_case(RING_BUF_MAX_ENTRIES - 1; "write one less than capacity items")]
#[test_case::test_case(RING_BUF_MAX_ENTRIES * 8; "write more items than capacity")]
fn ring_buf(n: usize) {
    let WithData(
        RingBufTest {
            mut ring_buf,
            regs,
            _bpf,
        },
        data,
    ) = WithData::new(n);

    // Note that after expected_capacity has been submitted, reserve calls in the probe will fail
    // and the probe will give up.
    let expected_capacity = RING_BUF_MAX_ENTRIES - 1;

    // Call the function that the uprobe is attached to with the data.
    let mut expected = Vec::new();
    let mut expected_rejected = 0u64;
    let mut expected_dropped = 0u64;
    for (i, &v) in data.iter().enumerate() {
        ring_buf_trigger_ebpf_program(v);
        if i >= expected_capacity {
            expected_dropped += 1;
        } else if v % 2 == 0 {
            expected.push(v);
        } else {
            expected_rejected += 1;
        }
    }

    let mut seen = Vec::<u64>::new();
    while seen.len() < expected.len() {
        if let Some(read) = ring_buf.next() {
            let read: [u8; 8] = (*read)
                .try_into()
                .with_context(|| format!("data: {:?}", read.len()))
                .unwrap();
            let arg = u64::from_ne_bytes(read);
            assert_eq!(arg % 2, 0, "got {arg} from probe");
            seen.push(arg);
        }
    }

    // Make sure that there is nothing else in the ring_buf.
    assert_matches!(ring_buf.next(), None);

    // Ensure that the data that was read matches what was passed, and the rejected count was set
    // properly.
    assert_eq!(seen, expected);
    let Registers { dropped, rejected } = regs.get(&0, 0).unwrap().iter().sum();
    assert_eq!(dropped, expected_dropped);
    assert_eq!(rejected, expected_rejected);
}

#[test_case::test_case(RING_BUF_MAX_ENTRIES / 2; "write half the capacity items")]
// This test checks for a bug that the consumer index always started at position 0 of a
// newly-loaded ring-buffer map. This assumption is not true for a map that is pinned to the bpffs
// filesystem since the map "remembers" the last consumer index position even if all processes
// unloaded it
fn pinned_ring_buf(n: usize) {
    let run_test = |mut ring_buf: RingBuf<MapData>,
                    regs: PerCpuArray<MapData, Registers>,
                    data: Vec<u64>,
                    expected_capacity: usize| {
        let mut expected = Vec::new();
        let mut expected_rejected = 0u64;
        let mut expected_dropped = 0u64;

        for (i, &v) in data.iter().enumerate() {
            ring_buf_trigger_ebpf_program(v);
            if i >= expected_capacity {
                expected_dropped += 1;
            } else if v % 2 == 0 {
                expected.push(v);
            } else {
                expected_rejected += 1;
            }
        }

        let mut seen = Vec::<u64>::new();
        while seen.len() < expected.len() {
            if let Some(read) = ring_buf.next() {
                let read: [u8; 8] = (*read)
                    .try_into()
                    .with_context(|| format!("data: {:?}", read.len()))
                    .unwrap();
                let arg = u64::from_ne_bytes(read);
                assert_eq!(arg % 2, 0, "got {arg} from probe");
                seen.push(arg);
            }
        }

        assert_matches!(ring_buf.next(), None);
        assert_eq!(seen, expected);

        let Registers { dropped, rejected } = regs.get(&0, 0).unwrap().iter().sum();
        assert_eq!(dropped, expected_dropped);
        assert_eq!(rejected, expected_rejected);
    };

    // Note that after expected_capacity has been submitted, reserve calls in the probe will fail
    // and the probe will give up.
    let expected_capacity = RING_BUF_MAX_ENTRIES - 1;

    let PinnedWithData(
        PinnedRingBufTest {
            ring_buf,
            regs,
            _bpf,
        },
        data,
    ) = PinnedWithData::new(n);

    run_test(ring_buf, regs, data, expected_capacity);

    // Close pinned map and re-open
    drop(_bpf);

    let PinnedWithData(
        PinnedRingBufTest {
            ring_buf,
            regs,
            _bpf,
        },
        data,
    ) = PinnedWithData::new(n);
    // Clean up the pinned map from the filesystem
    fs::remove_file(RING_BUF_PIN_PATH).unwrap();

    run_test(ring_buf, regs, data, expected_capacity);
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn ring_buf_trigger_ebpf_program(arg: u64) {
    std::hint::black_box(arg);
}

// This test differs from the other async test in that it's possible for the producer
// to fill the ring_buf. We just ensure that the number of events we see is sane given
// what the producer sees, and that the logic does not hang. This exercises interleaving
// discards, successful commits, and drops due to the ring_buf being full.
#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn ring_buf_async_with_drops() {
    let WithData(
        RingBufTest {
            ring_buf,
            regs,
            _bpf,
        },
        data,
    ) = WithData::new(RING_BUF_MAX_ENTRIES * 8);

    let mut async_fd = AsyncFd::with_interest(ring_buf, Interest::READABLE).unwrap();

    // Spawn the writer which internally will spawn many parallel writers.
    // Construct an AsyncFd from the RingBuf in order to receive readiness notifications.
    let mut seen = 0;
    let mut process_ring_buf = |ring_buf: &mut RingBuf<_>| {
        while let Some(read) = ring_buf.next() {
            let read: [u8; 8] = (*read)
                .try_into()
                .with_context(|| format!("data: {:?}", read.len()))
                .unwrap();
            let arg = u64::from_ne_bytes(read);
            assert_eq!(arg % 2, 0, "got {arg} from probe");
            seen += 1;
        }
    };
    let mut writer =
        futures::future::try_join_all(data.chunks(8).map(ToOwned::to_owned).map(|v| {
            tokio::spawn(async {
                for value in v {
                    ring_buf_trigger_ebpf_program(value);
                }
            })
        }));
    loop {
        let readable = async_fd.readable_mut();
        futures::pin_mut!(readable);
        match futures::future::select(readable, &mut writer).await {
            futures::future::Either::Left((guard, _writer)) => {
                let mut guard = guard.unwrap();
                process_ring_buf(guard.get_inner_mut());
                guard.clear_ready();
            }
            futures::future::Either::Right((writer, readable)) => {
                writer.unwrap();

                // If there's more to read, we should receive a readiness notification in a timely
                // manner.  If we don't then, then assert that there's nothing else to read. Note
                // that it's important to wait some time before attempting to read, otherwise we may
                // catch up with the producer before epoll has an opportunity to send a
                // notification; our consumer thread can race with the kernel epoll check.
                match tokio::time::timeout(Duration::from_millis(10), readable).await {
                    Err(tokio::time::error::Elapsed { .. }) => (),
                    Ok(guard) => {
                        let mut guard = guard.unwrap();
                        process_ring_buf(guard.get_inner_mut());
                        guard.clear_ready();
                    }
                }

                break;
            }
        }
    }

    // Make sure that there is nothing else in the ring_buf.
    assert_matches!(async_fd.into_inner().next(), None);

    let max_dropped: u64 = u64::try_from(
        data.len()
            .checked_sub(RING_BUF_MAX_ENTRIES - 1)
            .unwrap_or_default(),
    )
    .unwrap();
    let max_seen = u64::try_from(data.iter().filter(|v| *v % 2 == 0).count()).unwrap();
    let max_rejected = u64::try_from(data.len()).unwrap() - max_seen;
    let Registers { dropped, rejected } = regs.get(&0, 0).unwrap().iter().sum();
    let total = u64::try_from(data.len()).unwrap();
    let min_seen = max_seen.checked_sub(max_dropped).unwrap_or_default();
    let min_rejected = max_rejected.checked_sub(dropped).unwrap_or_default();
    let facts = format!(
        "seen={seen}, rejected={rejected}, dropped={dropped}, total={total}, max_seen={max_seen}, \
        max_rejected={max_rejected}, max_dropped={max_dropped}",
    );
    assert_eq!(seen + rejected + dropped, total, "{facts}");
    assert!(
        (0u64..=max_dropped).contains(&dropped),
        "dropped={dropped} not in 0..={max_dropped}; {facts}",
    );
    assert!(
        (min_rejected..=max_rejected).contains(&rejected),
        "rejected={rejected} not in {min_rejected}..={max_rejected}; {facts}",
    );
    assert!(
        (min_seen..=max_seen).contains(&seen),
        "seen={seen} not in {min_seen}..={max_seen}, rejected={rejected}; {facts}",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn ring_buf_async_no_drop() {
    let WithData(
        RingBufTest {
            ring_buf,
            regs,
            _bpf,
        },
        data,
    ) = WithData::new(RING_BUF_MAX_ENTRIES * 3);

    let writer = {
        let mut rng = rand::rng();
        let data: Vec<_> = data
            .iter()
            .copied()
            .map(|value| (value, Duration::from_nanos(rng.random_range(0..10))))
            .collect();
        tokio::spawn(async move {
            for (value, duration) in data {
                // Sleep a tad so we feel confident that the consumer will keep up
                // and no messages will be dropped.
                tokio::time::sleep(duration).await;
                ring_buf_trigger_ebpf_program(value);
            }
        })
    };

    // Construct an AsyncFd from the RingBuf in order to receive readiness notifications.
    let mut async_fd = AsyncFd::with_interest(ring_buf, Interest::READABLE).unwrap();
    // Note that unlike in the synchronous case where all of the entries are written before any of
    // them are read, in this case we expect all of the entries to make their way to userspace
    // because entries are being consumed as they are produced.
    let expected: Vec<u64> = data.iter().cloned().filter(|v| *v % 2 == 0).collect();
    let expected_len = expected.len();
    let reader = async move {
        let mut seen = Vec::with_capacity(expected_len);
        while seen.len() < expected_len {
            let mut guard = async_fd.readable_mut().await.unwrap();
            let ring_buf = guard.get_inner_mut();
            while let Some(read) = ring_buf.next() {
                let read: [u8; 8] = (*read)
                    .try_into()
                    .with_context(|| format!("data: {:?}", read.len()))
                    .unwrap();
                let arg = u64::from_ne_bytes(read);
                seen.push(arg);
            }
            guard.clear_ready();
        }
        (seen, async_fd.into_inner())
    };
    let (writer, (seen, mut ring_buf)) = futures::future::join(writer, reader).await;
    writer.unwrap();

    // Make sure that there is nothing else in the ring_buf.
    assert_matches!(ring_buf.next(), None);

    // Ensure that the data that was read matches what was passed.
    assert_eq!(&seen, &expected);
    let Registers { dropped, rejected } = regs.get(&0, 0).unwrap().iter().sum();
    assert_eq!(dropped, 0);
    assert_eq!(rejected, (data.len() - expected.len()).try_into().unwrap());
}

// This test reproduces a bug where the ring buffer would not be notified of new entries if the
// state was not properly synchronized between the producer and consumer. This would result in the
// consumer never being woken up and the test hanging.
#[test_log::test]
fn ring_buf_epoll_wakeup() {
    let RingBufTest {
        mut ring_buf,
        _bpf,
        regs: _,
    } = RingBufTest::new();

    let epoll_fd = epoll::create(false).unwrap();
    epoll::ctl(
        epoll_fd,
        epoll::ControlOptions::EPOLL_CTL_ADD,
        ring_buf.as_raw_fd(),
        // The use of EPOLLET is intentional. Without it, level-triggering would result in
        // more notifications, and would mask the underlying bug this test reproduced when
        // the synchronization logic in the RingBuf mirrored that of libbpf. Also, tokio's
        // AsyncFd always uses this flag (as demonstrated in the subsequent test).
        epoll::Event::new(epoll::Events::EPOLLIN | epoll::Events::EPOLLET, 0),
    )
    .unwrap();
    let mut epoll_event_buf = [epoll::Event::new(epoll::Events::EPOLLIN, 0); 1];
    let mut total_events: u64 = 0;
    let writer = WriterThread::spawn();
    while total_events < WriterThread::NUM_MESSAGES {
        epoll::wait(epoll_fd, -1, &mut epoll_event_buf).unwrap();
        while let Some(read) = ring_buf.next() {
            assert_eq!(read.len(), 8);
            total_events += 1;
        }
    }
    writer.join();
}

// This test is like the above test but uses tokio and AsyncFd instead of raw epoll.
#[tokio::test]
#[test_log::test]
async fn ring_buf_asyncfd_events() {
    let RingBufTest {
        ring_buf,
        regs: _,
        _bpf,
    } = RingBufTest::new();

    let mut async_fd = AsyncFd::with_interest(ring_buf, Interest::READABLE).unwrap();
    let mut total_events = 0;
    let writer = WriterThread::spawn();
    while total_events < WriterThread::NUM_MESSAGES {
        let mut guard = async_fd.readable_mut().await.unwrap();
        let rb = guard.get_inner_mut();
        while let Some(read) = rb.next() {
            assert_eq!(read.len(), 8);
            total_events += 1;
        }
        guard.clear_ready();
    }
    writer.join();
}

// WriterThread triggers the ring_buf write continuously until the join() method is called. It is
// used by both the epoll and async fd test that need frequent writes to the ring buffer to trigger
// the memory synchronization bug that was fixed.
struct WriterThread {
    thread: thread::JoinHandle<()>,
    done: Arc<AtomicBool>,
}

impl WriterThread {
    // When the ring buffer implementation uses Ordering::Relaxed to write the consumer position
    // rather than Ordering::SeqCst, the test will hang. This number was determined to be large
    // enough to tickle that bug on a hardware accelerated VM with 2 vCPUs.
    const NUM_MESSAGES: u64 = 20_000;

    fn spawn() -> Self {
        let done = Arc::new(AtomicBool::new(false));
        Self {
            thread: {
                let done = done.clone();
                thread::spawn(move || {
                    while !done.load(Ordering::Relaxed) {
                        // Write 0 which is even and won't be rejected.
                        ring_buf_trigger_ebpf_program(0);
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
