use anyhow::Context as _;
use assert_matches::assert_matches;
use aya::{
    maps::{array::PerCpuArray, ring_buf::RingBuf, MapData},
    programs::{TracePoint, UProbe},
    Bpf, BpfLoader, Btf, Pod,
};
use aya_obj::generated::BPF_RINGBUF_HDR_SZ;
use core::panic;
use rand::Rng as _;
use std::os::fd::AsRawFd as _;
use tokio::{
    io::unix::AsyncFd,
    time::{sleep, Duration},
};

/// Generate a variable length vector of u64s.
struct RingBufTest {
    _bpf: Bpf,
    ring_buf: RingBuf<MapData>,
    regs: PerCpuArray<MapData, Registers>,
    data: Vec<u64>,
}

// This structure's definition is duplicated in the probe.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
struct Registers {
    dropped: u64,
    rejected: u64,
}

impl core::ops::Add for Registers {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            dropped: self.dropped + rhs.dropped,
            rejected: self.rejected + rhs.rejected,
        }
    }
}

impl<'a> std::iter::Sum<&'a Registers> for Registers {
    fn sum<I: Iterator<Item = &'a Registers>>(iter: I) -> Self {
        iter.fold(Default::default(), |a, b| a + *b)
    }
}

unsafe impl Pod for Registers {}

// Note that it is important for this test that RING_BUF_MAX_ENTRIES ends up creating a ring buffer
// that is exactly a power-of-two multiple of the page size. The synchronous test will fail if
// that's not the case because the actual size will be rounded up, and fewer entries will be dropped
// than expected.
const RING_BUF_MAX_ENTRIES: usize = 512;

impl RingBufTest {
    fn new() -> Self {
        const RING_BUF_BYTE_SIZE: u32 = (RING_BUF_MAX_ENTRIES
            * (core::mem::size_of::<u64>() + BPF_RINGBUF_HDR_SZ as usize))
            as u32;

        // Use the loader API to control the size of the ring_buf.
        let mut bpf = BpfLoader::new()
            .btf(Some(Btf::from_sys_fs().unwrap()).as_ref())
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
            Some("ring_buf_trigger_ebpf_program"),
            0,
            "/proc/self/exe",
            None,
        )
        .unwrap();

        let data = {
            let mut rng = rand::thread_rng();
            // Generate more entries than there is space so we can test dropping entries.
            let n = rng.gen_range(1..=RING_BUF_MAX_ENTRIES * 2);
            std::iter::repeat_with(|| rng.gen()).take(n).collect()
        };

        Self {
            _bpf: bpf,
            ring_buf,
            regs,
            data,
        }
    }
}

#[test]
fn ring_buf() {
    let RingBufTest {
        ring_buf,
        ref regs,
        ref data,
        ..
    } = &mut RingBufTest::new();

    // Note that after expected_capacity has been submitted, reserve calls in the probe will fail
    // and the probe will give up.
    let expected_capacity = RING_BUF_MAX_ENTRIES - 1;

    // Call the function that the uprobe is attached to with randomly generated data.
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

#[no_mangle]
#[inline(never)]
pub extern "C" fn ring_buf_trigger_ebpf_program(arg: u64) {
    std::hint::black_box(arg);
}

// This test differs from the other async test in that it's possible for the producer
// to fill the ring_buf. We just ensure that the number of events we see is sane given
// what the producer sees, and that the logic does not hang. This exercises interleaving
// discards, successful commits, and drops due to the ring_buf being full.
#[tokio::test(flavor = "multi_thread")]
async fn ring_buf_async_with_drops() {
    let RingBufTest {
        ring_buf,
        ref regs,
        ref data,
        _bpf,
    } = &mut RingBufTest::new();

    let raw_fd = ring_buf.as_raw_fd();
    let async_fd = AsyncFd::with_interest(raw_fd, tokio::io::Interest::READABLE).unwrap();

    // Spwan the writer which internally will spawn many parallel writers.
    // Construct an AsyncFd from the RingBuf in order to receive readiness notifications.
    let mut seen = 0;
    let mut process_ring_buf = || {
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
    use futures::future::{
        select,
        Either::{Left, Right},
    };
    let writer = futures::future::try_join_all(data.chunks(8).map(ToOwned::to_owned).map(|v| {
        tokio::spawn(async {
            for value in v {
                ring_buf_trigger_ebpf_program(value);
            }
        })
    }));
    let readable = {
        let mut writer = writer;
        loop {
            let readable = Box::pin(async_fd.readable());
            writer = match select(readable, writer).await {
                Left((guard, writer)) => {
                    let mut guard = guard.unwrap();
                    process_ring_buf();
                    guard.clear_ready();
                    writer
                }
                Right((writer, readable)) => {
                    writer.unwrap();
                    break readable;
                }
            }
        }
    };

    // If there's more to read, we should receive a readiness notification in a timely manner.
    // If we don't then, then assert that there's nothing else to read. Note that it's important
    // to wait some time before attempting to read, otherwise we may catch up with the producer
    // before epoll has an opportunity to send a notification; our consumer thread can race
    // with the kernel epoll check.
    let sleep_fut = sleep(Duration::from_millis(10));
    tokio::pin!(sleep_fut);
    match select(sleep_fut, readable).await {
        Left(((), _)) => {
            assert_matches!(ring_buf.next(), None);
        }
        Right((guard, _)) => {
            process_ring_buf();
            guard.unwrap().clear_ready();
        }
    }

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
    assert_eq!(seen + rejected + dropped, total, "{facts}",);
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
async fn ring_buf_async_no_drop() {
    let RingBufTest {
        ring_buf,
        ref regs,
        ref data,
        _bpf,
    } = &mut RingBufTest::new();

    let writer = {
        let data = data.to_owned();
        tokio::spawn(async move {
            for value in data {
                // Sleep a tad so we feel confident that the consumer will keep up
                // and no messages will be dropped.
                let dur = Duration::from_nanos(rand::thread_rng().gen_range(0..10));
                sleep(dur).await;
                ring_buf_trigger_ebpf_program(value);
            }
        })
    };

    // Construct an AsyncFd from the RingBuf in order to receive readiness notifications.
    let async_fd = AsyncFd::new(ring_buf.as_raw_fd()).unwrap();
    // Note that unlike in the synchronous case where all of the entries are written before any of
    // them are read, in this case we expect all of the entries to make their way to userspace
    // because entries are being consumed as they are produced.
    let expected: Vec<u64> = data.iter().cloned().filter(|v| *v % 2 == 0).collect();
    let expected_len = expected.len();
    let reader = async {
        let mut seen = Vec::with_capacity(expected_len);
        while seen.len() < expected_len {
            let mut guard = async_fd.readable().await.unwrap();
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
        seen
    };
    let (writer, seen) = futures::future::join(writer, reader).await;
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
#[test]
fn ring_buf_epoll_wakeup() {
    let mut bpf = Bpf::load(crate::RING_BUF_SCHED_TRACEPOINT).unwrap();
    let rb = bpf.take_map("rb").unwrap();
    let mut rb = RingBuf::try_from(rb).unwrap();
    let prog: &mut TracePoint = bpf.program_mut("sched_switch").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("sched", "sched_switch").unwrap();

    let epoll_fd = epoll::create(false).unwrap();
    epoll::ctl(
        epoll_fd,
        epoll::ControlOptions::EPOLL_CTL_ADD,
        rb.as_raw_fd(),
        // The use of EPOLLET is intentional. Without it, level-triggering would result in
        // more notifications, and would mask the underlying bug this test reproduced when
        // the synchronization logic in the RingBuf mirrored that of libbpf. Also, tokio's
        // AsyncFd always uses this flag (as demonstrated in the subsequent test).
        epoll::Event::new(epoll::Events::EPOLLIN | epoll::Events::EPOLLET, 0),
    )
    .unwrap();
    let mut epoll_event_buf = [epoll::Event::new(epoll::Events::EPOLLIN, 0); 1];
    let mut total_events = 0;
    while total_events < 1_000_000 {
        epoll::wait(epoll_fd, -1, &mut epoll_event_buf).unwrap();
        let mut events_after_wake = 0;
        while let Some(read) = rb.next() {
            assert_eq!(read.len(), 8);
            events_after_wake += 1;
            total_events += 1;
        }
        assert_ne!(events_after_wake, 0);
    }
}

// This test is like the above test but uses tokio and AsyncFd instead of raw epoll.
#[tokio::test]
async fn ring_buf_asyncfd_events() {
    let mut bpf = Bpf::load(crate::RING_BUF_SCHED_TRACEPOINT).unwrap();
    let rb = bpf.take_map("rb").unwrap();
    let mut rb = RingBuf::try_from(rb).unwrap();
    let prog: &mut TracePoint = bpf.program_mut("sched_switch").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("sched", "sched_switch").unwrap();

    let async_fd = AsyncFd::new(rb.as_raw_fd()).unwrap();
    let mut total_events = 0;
    while total_events < 1_000_000 {
        let mut guard = async_fd.readable().await.unwrap();
        let mut events_after_wake = 0;
        while let Some(read) = rb.next() {
            assert_eq!(read.len(), 8);
            events_after_wake += 1;
            total_events += 1;
        }
        guard.clear_ready();
        assert_ne!(events_after_wake, 0);
    }
}
