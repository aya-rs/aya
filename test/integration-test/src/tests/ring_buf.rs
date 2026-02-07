use std::{
    os::fd::AsRawFd as _,
    path::Path,
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
    maps::{MapData, array::PerCpuArray, ring_buf::RingBuf},
    programs::UProbe,
};
use aya_obj::generated::BPF_RINGBUF_HDR_SZ;
use integration_common::ring_buf::Registers;
use rand::Rng as _;
use scopeguard::defer;
use tokio::io::{Interest, unix::AsyncFd};

struct RingBufTest {
    bpf: Ebpf,
    ring_buf: RingBuf<MapData>,
    regs: PerCpuArray<MapData, Registers>,
}

const RING_BUF: &str = "RING_BUF";
const RING_BUF_LEGACY: &str = "RING_BUF_LEGACY";
const RING_BUF_MISMATCH: &str = "RING_BUF_MISMATCH";

const ALL_RING_BUFS: &[&str] = &[RING_BUF, RING_BUF_LEGACY, RING_BUF_MISMATCH];

#[derive(Clone, Copy)]
struct RingBufVariant {
    map: &'static str,
    regs: &'static str,
    prog: &'static str,
}

const RING_BUF_VARIANTS: &[RingBufVariant] = &[
    RingBufVariant {
        map: RING_BUF,
        regs: "REGISTERS",
        prog: "ring_buf_test",
    },
    RingBufVariant {
        map: RING_BUF_LEGACY,
        regs: "REGISTERS_LEGACY",
        prog: "ring_buf_test_legacy",
    },
];

// Note that it is important for this test that RING_BUF_MAX_ENTRIES ends up creating a ring buffer
// that is exactly a power-of-two multiple of the page size. The synchronous test will fail if
// that's not the case because the actual size will be rounded up, and fewer entries will be dropped
// than expected.
const RING_BUF_MAX_ENTRIES: usize = 512;

impl RingBufTest {
    fn new(variant: RingBufVariant) -> Self {
        Self::new_with_mutators(variant, |_loader| {}, |_bpf| {})
    }

    // Allows the test to mutate the EbpfLoader before it loads the object file from disk, and to
    // mutate the loaded Ebpf object after it has been loaded from disk but before it is loaded
    // into the kernel.
    fn new_with_mutators<'loader>(
        variant: RingBufVariant,
        loader_fn: impl FnOnce(&mut EbpfLoader<'loader>),
        bpf_fn: impl FnOnce(&mut Ebpf),
    ) -> Self {
        const RING_BUF_BYTE_SIZE: u32 =
            (RING_BUF_MAX_ENTRIES * (size_of::<u64>() + BPF_RINGBUF_HDR_SZ as usize)) as u32;

        // Use the loader API to control the size of the ring_buf.
        let mut loader = EbpfLoader::new();
        for &map in ALL_RING_BUFS {
            loader.map_max_entries(map, RING_BUF_BYTE_SIZE);
        }
        loader_fn(&mut loader);
        let mut bpf = loader.load(crate::RING_BUF).unwrap();
        bpf_fn(&mut bpf);
        let ring_buf = bpf.take_map(variant.map).unwrap();
        let ring_buf = RingBuf::try_from(ring_buf).unwrap();
        let regs = bpf.take_map(variant.regs).unwrap();
        let regs = PerCpuArray::<_, Registers>::try_from(regs).unwrap();
        let prog: &mut UProbe = bpf.program_mut(variant.prog).unwrap().try_into().unwrap();
        prog.load().unwrap();
        match prog {
            UProbe::Single(p) => p.attach("ring_buf_trigger_ebpf_program", "/proc/self/exe", None),
            UProbe::Multi(_) => panic!("expected single-attach program"),
            UProbe::Unknown(_) => panic!("unexpected unknown uprobe mode for loaded program"),
        }
        .unwrap();

        Self {
            bpf,
            ring_buf,
            regs,
        }
    }
}

struct WithData(RingBufTest, Vec<u64>);

impl WithData {
    fn new(n: usize, variant: RingBufVariant) -> Self {
        Self(RingBufTest::new(variant), {
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
    for &variant in RING_BUF_VARIANTS {
        let WithData(
            RingBufTest {
                mut ring_buf,
                regs,
                bpf: _bpf,
            },
            data,
        ) = WithData::new(n, variant);

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
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn ring_buf_trigger_ebpf_program(arg: u64) {
    std::hint::black_box(arg);
}

fn ring_buf_mismatch_size<T>(
    map: &'static str,
    prog: &'static str,
    trigger_symbol: &'static str,
    trigger: extern "C" fn(u64),
    value: T,
    decode: fn(&[u8]) -> T,
) where
    T: Copy + Into<u64> + PartialEq + std::fmt::Debug,
{
    const RING_BUF_BYTE_SIZE: u32 =
        (RING_BUF_MAX_ENTRIES * (size_of::<u64>() + BPF_RINGBUF_HDR_SZ as usize)) as u32;
    let mut loader = EbpfLoader::new();
    for &map in ALL_RING_BUFS {
        loader.map_max_entries(map, RING_BUF_BYTE_SIZE);
    }
    let mut bpf = loader.load(crate::RING_BUF).unwrap();
    let ring_buf = bpf.take_map(map).unwrap();
    let mut ring_buf = RingBuf::try_from(ring_buf).unwrap();
    let prog: &mut UProbe = bpf.program_mut(prog).unwrap().try_into().unwrap();
    prog.load().unwrap();
    match prog {
        UProbe::Single(p) => p.attach(trigger_symbol, "/proc/self/exe", None),
        UProbe::Multi(_) => panic!("expected single-attach program"),
        UProbe::Unknown(_) => panic!("unexpected unknown uprobe mode for loaded program"),
    }
    .unwrap();

    trigger(value.into());
    {
        let read = ring_buf.next().unwrap();
        assert_eq!(read.len(), size_of::<T>());
        let decoded = decode(read.as_ref());
        assert_eq!(decoded, value);
    }
    assert_matches!(ring_buf.next(), None);
}

#[test_log::test]
fn ring_buf_mismatch_small() {
    let value: u16 = 0xbeef;
    ring_buf_mismatch_size(
        RING_BUF_MISMATCH,
        "ring_buf_mismatch_small",
        "ring_buf_trigger_ebpf_program",
        ring_buf_trigger_ebpf_program,
        value,
        |read| {
            let bytes: [u8; 2] = read.try_into().unwrap();
            u16::from_ne_bytes(bytes)
        },
    );
}

#[test_log::test]
fn ring_buf_mismatch_large() {
    let value: u64 = 0xdead_beef_dead_beef;
    ring_buf_mismatch_size(
        RING_BUF_MISMATCH,
        "ring_buf_mismatch_large",
        "ring_buf_trigger_ebpf_program",
        ring_buf_trigger_ebpf_program,
        value,
        |read| {
            let bytes: [u8; 8] = read.try_into().unwrap();
            u64::from_ne_bytes(bytes)
        },
    );
}

// This test differs from the other async test in that it's possible for the producer
// to fill the ring_buf. We just ensure that the number of events we see is sane given
// what the producer sees, and that the logic does not hang. This exercises interleaving
// discards, successful commits, and drops due to the ring_buf being full.
#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn ring_buf_async_with_drops() {
    for &variant in RING_BUF_VARIANTS {
        let WithData(
            RingBufTest {
                ring_buf,
                regs,
                bpf: _bpf,
            },
            data,
        ) = WithData::new(RING_BUF_MAX_ENTRIES * 8, variant);

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

        let max_dropped: u64 =
            u64::try_from(data.len().saturating_sub(RING_BUF_MAX_ENTRIES - 1)).unwrap();
        let max_seen = u64::try_from(data.iter().filter(|v| *v % 2 == 0).count()).unwrap();
        let max_rejected = u64::try_from(data.len()).unwrap() - max_seen;
        let Registers { dropped, rejected } = regs.get(&0, 0).unwrap().iter().sum();
        let total = u64::try_from(data.len()).unwrap();
        let min_seen = max_seen.saturating_sub(max_dropped);
        let min_rejected = max_rejected.saturating_sub(dropped);
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
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn ring_buf_async_no_drop() {
    for &variant in RING_BUF_VARIANTS {
        let WithData(
            RingBufTest {
                ring_buf,
                regs,
                bpf: _bpf,
            },
            data,
        ) = WithData::new(RING_BUF_MAX_ENTRIES * 3, variant);

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
        let expected: Vec<u64> = data.iter().copied().filter(|v| *v % 2 == 0).collect();
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
}

// This test reproduces a bug where the ring buffer would not be notified of new entries if the
// state was not properly synchronized between the producer and consumer. This would result in the
// consumer never being woken up and the test hanging.
#[test_log::test]
fn ring_buf_epoll_wakeup() {
    for &variant in RING_BUF_VARIANTS {
        let RingBufTest {
            mut ring_buf,
            bpf: _bpf,
            regs: _,
        } = RingBufTest::new(variant);

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
}

// This test is like the above test but uses tokio and AsyncFd instead of raw epoll.
#[tokio::test]
#[test_log::test]
async fn ring_buf_asyncfd_events() {
    for &variant in RING_BUF_VARIANTS {
        let RingBufTest {
            ring_buf,
            regs: _,
            bpf: _bpf,
        } = RingBufTest::new(variant);

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
                let done = Arc::clone(&done);
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

// This tests that a ring buffer can be pinned and then re-opened and attached to a subsequent
// program. It ensures that the producer position is properly synchronized between the two
// programs, and that no unread data is lost.
#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn ring_buf_pinned() {
    for &variant in RING_BUF_VARIANTS {
        let pin_path =
            Path::new("/sys/fs/bpf/").join(format!("ring_buf_{}", rand::rng().random::<u64>()));

        let RingBufTest {
            mut ring_buf,
            regs: _,
            bpf,
        } = RingBufTest::new_with_mutators(
            variant,
            |_loader| {},
            |bpf| {
                let ring_buf = bpf.map_mut(variant.map).unwrap();
                ring_buf.pin(&pin_path).unwrap();
            },
        );
        defer! { std::fs::remove_file(&pin_path).unwrap() }

        // Write a few items to the ring buffer.
        let to_write_before_reopen = [2, 4, 6, 8];
        for v in to_write_before_reopen {
            ring_buf_trigger_ebpf_program(v);
        }
        let (to_read_before_reopen, to_read_after_reopen) = to_write_before_reopen.split_at(2);
        for v in to_read_before_reopen {
            let item = ring_buf.next().unwrap();
            let item: [u8; 8] = item.as_ref().try_into().unwrap();
            assert_eq!(item, v.to_ne_bytes());
        }
        drop(ring_buf);
        drop(bpf);

        // Reopen the ring buffer using the pinned map.
        let RingBufTest {
            mut ring_buf,
            regs: _,
            bpf: _bpf,
        } = RingBufTest::new_with_mutators(
            variant,
            |loader| {
                loader.map_pin_path(variant.map, &pin_path);
            },
            |_bpf| {},
        );
        let to_write_after_reopen = [10, 12];

        // Write some more data.
        for v in to_write_after_reopen {
            ring_buf_trigger_ebpf_program(v);
        }
        // Read both the data that was written before the ring buffer was reopened and the data that
        // was written after it was reopened.
        for v in to_read_after_reopen
            .iter()
            .chain(to_write_after_reopen.iter())
        {
            let item = ring_buf.next().unwrap();
            let item: [u8; 8] = item.as_ref().try_into().unwrap();
            assert_eq!(item, v.to_ne_bytes());
        }
        // Make sure there is nothing else in the ring buffer.
        assert_matches!(ring_buf.next(), None);
    }
}
