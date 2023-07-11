use anyhow::Context as _;
use aya::{
    maps::{array::Array, ring_buf::RingBuf, MapData},
    programs::{TracePoint, UProbe},
    Bpf, BpfLoader, Btf, Pod,
};
use aya_obj::generated::BPF_RINGBUF_HDR_SZ;
use core::panic;
use futures::{select_biased, FutureExt as _};
use matches::assert_matches;
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
    regs: Array<MapData, Registers>,
    data: Vec<u64>,
}

// This structure's definition is duplicated in the probe.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Registers {
    dropped: u64,
    rejected: u64,
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
        let regs = Array::<_, Registers>::try_from(regs).unwrap();
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

#[tokio::test]
async fn ring_buf() {
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
        if let Some(item) = ring_buf.next() {
            let item: [u8; 8] = (*item).try_into().unwrap();
            let arg = u64::from_ne_bytes(item);
            seen.push(arg);
        }
    }

    // Make sure that there is nothing else in the ring_buf.
    assert_matches!(ring_buf.next(), None);

    // Ensure that the data that was read matches what was passed, and the rejected count was set
    // properly.
    assert_eq!(seen, expected);
    assert_eq!(
        regs.get(&0, 0).unwrap(),
        Registers {
            dropped: expected_dropped,
            rejected: expected_rejected,
        }
    );
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

    let writer_data = data.clone();
    let writer = async move {
        let writers = writer_data.chunks(64).map(|v| {
            let writer_chunk = Vec::from(v);
            tokio::spawn(async move {
                for value in writer_chunk {
                    ring_buf_trigger_ebpf_program(value);
                }
            })
        });
        futures::future::try_join_all(writers).await.unwrap()
    };
    // Spwan the writer which internally will spawn many parallel writers.
    let mut writer = tokio::spawn(writer).fuse();
    // Construct an AsyncFd from the RingBuf in order to receive readiness notifications.
    let async_fd = AsyncFd::new(ring_buf.as_raw_fd()).unwrap();
    let mut process_events = || {
        let mut got = 0;
        while let Some(read) = ring_buf.next() {
            got += 1;
            let read: [u8; 8] = (*read)
                .try_into()
                .context(format!("data: {:?}", read.len()))
                .unwrap();
            let arg = u64::from_ne_bytes(read);
            if arg % 2 != 0 {
                panic!("got an odd number from the probe");
            }
        }
        got
    };
    let mut seen = 0;
    loop {
        let readable = async_fd.readable().fuse();
        tokio::pin!(readable);
        select_biased! {
            guard = readable => {
                seen += process_events();
                guard.unwrap().clear_ready();
            }
            writer = writer => {
                writer.unwrap() ;
                break;
            },
        };
    }
    let max_dropped: u64 = data
        .len()
        .checked_sub(RING_BUF_MAX_ENTRIES - 1)
        .unwrap_or_default()
        .try_into()
        .unwrap();
    let max_seen: u64 = data
        .iter()
        .filter(|v| *v % 2 == 0)
        .count()
        .try_into()
        .unwrap();
    let max_rejected = u64::try_from(data.len()).unwrap() - max_seen;
    let Registers { dropped, rejected } = regs.get(&0, 0).unwrap();
    assert_in(dropped, 0u64..=max_dropped);
    assert_in(rejected, rejected - dropped..=max_rejected);
    assert_in(seen, max_seen - dropped..=max_seen);

    fn assert_in(val: u64, range: impl core::ops::RangeBounds<u64> + core::fmt::Debug) {
        if !range.contains(&val) {
            panic!("{range:?} does not contain {val}")
        }
    }
}

#[tokio::test]
async fn ring_buf_async_no_drop() {
    let RingBufTest {
        ring_buf,
        ref regs,
        ref data,
        _bpf,
    } = &mut RingBufTest::new();

    let writer = async move {
        let mut rng = rand::thread_rng();
        for &value in data {
            // Sleep a tad so we feel confident that the consumer will keep up
            // and no messages will be dropped.
            sleep(Duration::from_nanos(rng.gen_range(0..1000))).await;
            ring_buf_trigger_ebpf_program(value);
        }
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
                    .context(format!("data: {:?}", read.len()))
                    .unwrap();
                let arg = u64::from_ne_bytes(read);
                seen.push(arg);
            }
            guard.clear_ready();
        }
        seen
    };
    let ((), seen) = futures::future::join(writer, reader).await;

    // Make sure that there is nothing else in the ring_buf.
    assert_matches!(ring_buf.next(), None);

    // Ensure that the data that was read matches what was passed.
    assert_eq!(&seen, &expected);
    assert_eq!(
        regs.get(&0, 0).unwrap(),
        Registers {
            dropped: 0,
            rejected: (data.len() - expected.len()).try_into().unwrap(),
        }
    );
}

// This test reproduces a bug where the ring buffer would not be notified of new entries if the
// state was not properly synchronized between the producer and consumer. This would result in the
// consumer never being woken up and the test hanging.
#[test]
fn ring_buf_epoll_wakeup() {
    let mut bpf = Bpf::load(crate::RING_BUF_SCHED_TRACEPOINT).unwrap();
    let rb = bpf.take_map("rb").unwrap();
    let mut rb = RingBuf::try_from(rb).unwrap();
    let prog: &mut TracePoint = bpf.program_mut("tracepoint").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("sched", "sched_switch").unwrap();

    let epoll_fd = epoll::create(false).unwrap();
    epoll::ctl(
        epoll_fd,
        epoll::ControlOptions::EPOLL_CTL_ADD,
        rb.as_raw_fd(),
        // The use of EPOLLET is intentional and key to the purpose of the test. libbpf does not use
        // it and avoid suffering from some lost notifications because of that.
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
    let prog: &mut TracePoint = bpf.program_mut("tracepoint").unwrap().try_into().unwrap();
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
