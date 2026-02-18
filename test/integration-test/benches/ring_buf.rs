#![expect(unused_crate_dependencies, reason = "used in benchmarks")]

use std::{
    convert::Infallible,
    ops::ControlFlow,
    os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
    thread,
    time::{Duration, Instant},
};

use aya::{
    Ebpf, EbpfLoader,
    maps::{MapData, ring_buf::RingBuf},
    programs::UProbe,
};
use aya_obj::generated::BPF_RINGBUF_HDR_SZ;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

const RING_BUF: &str = "RING_BUF";
const RING_BUF_LEGACY: &str = "RING_BUF_LEGACY";
const RING_BUF_MISMATCH: &str = "RING_BUF_MISMATCH";
const ALL_RING_BUFS: &[&str] = &[RING_BUF, RING_BUF_LEGACY, RING_BUF_MISMATCH];

const RING_BUF_MAX_ENTRIES: usize = 256 * 1024;
const PREFILL_SIZES: &[usize] = &[1, 8, 32, 128, 256, 1024, 4096, 16384];

const OVERLAP_EVENTS_PER_ITER: usize = 8192;
const BURST_ITEMS: usize = 16 * 1024;
const BURSTS_PER_ITER: usize = 8;
const BURST_TOTAL_ITEMS: usize = BURST_ITEMS * BURSTS_PER_ITER;

#[derive(Clone, Copy)]
enum Mode {
    Next,
    Batch,
    TryFold,
}

impl Mode {
    const fn name(self) -> &'static str {
        match self {
            Self::Next => "next",
            Self::Batch => "batch",
            Self::TryFold => "try_fold",
        }
    }
}

struct RingBufBench {
    _bpf: Ebpf,
    ring_buf: RingBuf<MapData>,
}

#[unsafe(no_mangle)]
#[inline(never)]
const extern "C" fn ring_buf_trigger_ebpf_program(arg: u64) {
    std::hint::black_box(arg);
}

impl RingBufBench {
    fn new() -> Self {
        const RING_BUF_BYTE_SIZE: u32 =
            (RING_BUF_MAX_ENTRIES * (size_of::<u64>() + BPF_RINGBUF_HDR_SZ as usize)) as u32;

        let mut loader = EbpfLoader::new();
        for &map in ALL_RING_BUFS {
            loader.map_max_entries(map, RING_BUF_BYTE_SIZE);
        }
        let mut bpf = loader.load(integration_test::RING_BUF).unwrap();

        let ring_buf = bpf.take_map(RING_BUF).unwrap();
        let ring_buf = RingBuf::try_from(ring_buf).unwrap();

        let prog: &mut UProbe = bpf
            .program_mut("ring_buf_test")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        prog.attach("ring_buf_trigger_ebpf_program", "/proc/self/exe", None)
            .unwrap();

        Self {
            _bpf: bpf,
            ring_buf,
        }
    }

    fn drain_count(&mut self, mode: Mode) -> usize {
        match mode {
            Mode::Next => {
                let mut seen = 0usize;
                while let Some(item) = self.ring_buf.next() {
                    let bytes: [u8; 8] = item.as_ref().try_into().unwrap();
                    std::hint::black_box(u64::from_ne_bytes(bytes));
                    seen += 1;
                }
                seen
            }
            Mode::Batch => {
                let mut seen = 0usize;
                let mut batch = self.ring_buf.batch();
                while let Some(item) = batch.next() {
                    let bytes: [u8; 8] = item.as_ref().try_into().unwrap();
                    std::hint::black_box(u64::from_ne_bytes(bytes));
                    seen += 1;
                }
                seen
            }
            Mode::TryFold => match self.ring_buf.try_fold(0usize, |seen, data| {
                let bytes: [u8; 8] = data.try_into().unwrap();
                std::hint::black_box(u64::from_ne_bytes(bytes));
                ControlFlow::<Infallible, usize>::Continue(seen + 1)
            }) {
                ControlFlow::Continue(seen) => seen,
                ControlFlow::Break(never) => match never {},
            },
        }
    }
}

fn run_overlap_count(bench: &mut RingBufBench, mode: Mode, events_per_iter: usize) -> Duration {
    let _seen = bench.drain_count(Mode::Batch);

    let epoll_fd = epoll::create(true).unwrap();
    let epoll_fd = unsafe { OwnedFd::from_raw_fd(epoll_fd) };
    epoll::ctl(
        epoll_fd.as_raw_fd(),
        epoll::ControlOptions::EPOLL_CTL_ADD,
        bench.ring_buf.as_raw_fd(),
        epoll::Event::new(epoll::Events::EPOLLIN, 0),
    )
    .unwrap();
    let mut epoll_event_buf = [epoll::Event::new(epoll::Events::EPOLLIN, 0); 1];

    let writer = thread::spawn(move || {
        for i in 0..events_per_iter {
            ring_buf_trigger_ebpf_program(u64::try_from(i).unwrap() * 2);
        }
    });

    let mut elapsed = Duration::ZERO;
    let mut seen = 0usize;
    while seen < events_per_iter {
        epoll::wait(epoll_fd.as_raw_fd(), -1, &mut epoll_event_buf).unwrap();
        let start = Instant::now();
        seen += bench.drain_count(mode);
        elapsed += start.elapsed();
    }

    writer.join().unwrap();
    assert_eq!(seen, events_per_iter);
    elapsed
}

fn run_bursty_count(bench: &mut RingBufBench, mode: Mode) -> Duration {
    let _seen = bench.drain_count(Mode::Batch);

    let epoll_fd = epoll::create(true).unwrap();
    let epoll_fd = unsafe { OwnedFd::from_raw_fd(epoll_fd) };
    epoll::ctl(
        epoll_fd.as_raw_fd(),
        epoll::ControlOptions::EPOLL_CTL_ADD,
        bench.ring_buf.as_raw_fd(),
        epoll::Event::new(epoll::Events::EPOLLIN, 0),
    )
    .unwrap();
    let mut epoll_event_buf = [epoll::Event::new(epoll::Events::EPOLLIN, 0); 1];

    let writer = thread::spawn(|| {
        for _ in 0..BURSTS_PER_ITER {
            for i in 0..BURST_ITEMS {
                ring_buf_trigger_ebpf_program(u64::try_from(i).unwrap() * 2);
            }
            thread::sleep(Duration::from_micros(200));
        }
    });

    let mut elapsed = Duration::ZERO;
    let mut seen = 0usize;
    while seen < BURST_TOTAL_ITEMS {
        epoll::wait(epoll_fd.as_raw_fd(), -1, &mut epoll_event_buf).unwrap();
        let start = Instant::now();
        seen += bench.drain_count(mode);
        elapsed += start.elapsed();
    }

    writer.join().unwrap();
    assert_eq!(seen, BURST_TOTAL_ITEMS);
    elapsed
}

fn bench_prefilled(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buf/prefilled");
    for &size in PREFILL_SIZES {
        group.throughput(Throughput::Elements(u64::try_from(size).unwrap()));
        for mode in [Mode::Next, Mode::Batch, Mode::TryFold] {
            group.bench_with_input(BenchmarkId::new(mode.name(), size), &size, |b, &size| {
                let mut bench = RingBufBench::new();
                b.iter_custom(|iters| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iters {
                        for i in 0..size {
                            ring_buf_trigger_ebpf_program(u64::try_from(i).unwrap() * 2);
                        }
                        let start = Instant::now();
                        assert_eq!(bench.drain_count(mode), size);
                        elapsed += start.elapsed();
                    }
                    elapsed
                });
            });
        }
    }
    group.finish();
}

fn bench_epoll_overlap_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buf/overlap_drain_only");
    group.throughput(Throughput::Elements(
        u64::try_from(OVERLAP_EVENTS_PER_ITER).unwrap(),
    ));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));
    for mode in [Mode::Next, Mode::Batch, Mode::TryFold] {
        group.bench_function(mode.name(), |b| {
            let mut bench = RingBufBench::new();
            b.iter_custom(|iters| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iters {
                    elapsed += run_overlap_count(&mut bench, mode, OVERLAP_EVENTS_PER_ITER);
                }
                elapsed
            });
        });
    }
    group.finish();
}

fn bench_epoll_bursty_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buf/bursty_drain_only");
    group.throughput(Throughput::Elements(
        u64::try_from(BURST_TOTAL_ITEMS).unwrap(),
    ));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));
    for mode in [Mode::Next, Mode::Batch, Mode::TryFold] {
        group.bench_function(mode.name(), |b| {
            let mut bench = RingBufBench::new();
            b.iter_custom(|iters| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iters {
                    elapsed += run_bursty_count(&mut bench, mode);
                }
                elapsed
            });
        });
    }
    group.finish();
}

criterion_group!(
    ring_buf_benches,
    bench_prefilled,
    bench_epoll_overlap_count,
    bench_epoll_bursty_count
);
criterion_main!(ring_buf_benches);
