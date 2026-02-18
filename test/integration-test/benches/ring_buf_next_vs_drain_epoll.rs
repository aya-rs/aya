#![expect(unused_crate_dependencies, reason = "used in tests")]

use std::{
    hint::black_box,
    os::fd::AsRawFd,
    thread,
    time::{Duration, Instant},
};

use aya::{
    Ebpf, EbpfLoader,
    maps::{MapData, array::PerCpuArray, ring_buf::RingBuf},
    programs::UProbe,
};
use aya_obj::generated::BPF_RINGBUF_HDR_SZ;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use integration_common::ring_buf::Registers;

struct RingBufBench {
    _bpf: Ebpf,
    ring_buf: RingBuf<MapData>,
    regs: PerCpuArray<MapData, Registers>,
}

const RING_BUF_MAX_ENTRIES: usize = 32 * 1024;
const ALL_RING_BUFS: &[&str] = &["RING_BUF", "RING_BUF_LEGACY", "RING_BUF_MISMATCH"];

#[derive(Clone, Copy)]
struct RingBufVariant {
    map: &'static str,
    regs: &'static str,
    prog: &'static str,
}

const RING_BUF_VARIANTS: &[RingBufVariant] = &[
    RingBufVariant {
        map: "RING_BUF",
        regs: "REGISTERS",
        prog: "ring_buf_test",
    },
    RingBufVariant {
        map: "RING_BUF_LEGACY",
        regs: "REGISTERS_LEGACY",
        prog: "ring_buf_test_legacy",
    },
];

#[derive(Clone, Copy)]
enum Mode {
    Next,
    Drain,
}

impl RingBufBench {
    fn new(variant: RingBufVariant) -> Self {
        const RING_BUF_BYTE_SIZE: u32 =
            (RING_BUF_MAX_ENTRIES * (size_of::<u64>() + BPF_RINGBUF_HDR_SZ as usize)) as u32;

        let mut loader = EbpfLoader::new();
        for &map in ALL_RING_BUFS {
            loader.map_max_entries(map, RING_BUF_BYTE_SIZE);
        }
        let mut bpf = loader.load(integration_test::RING_BUF).unwrap();

        let ring_buf = bpf.take_map(variant.map).unwrap();
        let ring_buf = RingBuf::try_from(ring_buf).unwrap();
        let regs = bpf.take_map(variant.regs).unwrap();
        let regs = PerCpuArray::<_, Registers>::try_from(regs).unwrap();

        let prog: &mut UProbe = bpf.program_mut(variant.prog).unwrap().try_into().unwrap();
        prog.load().unwrap();
        prog.attach("ring_buf_trigger_ebpf_program", "/proc/self/exe", None)
            .unwrap();

        Self {
            _bpf: bpf,
            ring_buf,
            regs,
        }
    }

    fn registers(&self) -> Registers {
        self.regs.get(&0, 0).unwrap().iter().sum()
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn ring_buf_trigger_ebpf_program(arg: u64) {
    black_box(arg);
}

fn drain_once(ring_buf: &mut RingBuf<MapData>, mode: Mode) -> usize {
    match mode {
        Mode::Next => {
            let mut seen = 0usize;
            while let Some(item) = ring_buf.next() {
                let _: [u8; 8] = (*item).try_into().unwrap();
                seen += 1;
            }
            seen
        }
        Mode::Drain => {
            let mut seen = 0usize;
            let stats = ring_buf.drain(|item| {
                let _: [u8; 8] = item.try_into().unwrap();
                seen += 1;
            });
            assert_eq!(stats.read, seen);
            seen
        }
    }
}

fn run_overlap(bench: &mut RingBufBench, mode: Mode, events_per_iter: usize) -> (usize, Duration) {
    // Drain leftovers from previous iteration.
    let _ = drain_once(&mut bench.ring_buf, Mode::Next);

    let before = bench.registers();

    let epoll_fd = epoll::create(false).unwrap();
    epoll::ctl(
        epoll_fd,
        epoll::ControlOptions::EPOLL_CTL_ADD,
        bench.ring_buf.as_raw_fd(),
        epoll::Event::new(epoll::Events::EPOLLIN | epoll::Events::EPOLLET, 0),
    )
    .unwrap();
    let mut epoll_event_buf = [epoll::Event::new(epoll::Events::EPOLLIN, 0); 1];

    let writer = thread::spawn(move || {
        for _ in 0..events_per_iter {
            ring_buf_trigger_ebpf_program(0);
        }
    });

    let start = Instant::now();
    let mut seen = 0usize;
    while seen < events_per_iter {
        epoll::wait(epoll_fd, -1, &mut epoll_event_buf).unwrap();
        seen += drain_once(&mut bench.ring_buf, mode);
    }
    let elapsed = start.elapsed();

    writer.join().unwrap();
    nix::unistd::close(epoll_fd).unwrap();

    let after = bench.registers();
    let dropped_delta = after.dropped - before.dropped;
    let rejected_delta = after.rejected - before.rejected;
    assert_eq!(rejected_delta, 0);
    // We expect no drops in this shape; fail loudly if we saturate.
    assert_eq!(dropped_delta, 0);
    assert_eq!(seen, events_per_iter);

    (seen, elapsed)
}

fn bench_ring_buf_next_vs_drain_epoll(c: &mut Criterion) {
    const EVENTS_PER_ITER: usize = 8_192;

    let mut group = c.benchmark_group("ring_buf/next_vs_drain_epoll_overlap");
    group.throughput(criterion::Throughput::Elements(
        u64::try_from(EVENTS_PER_ITER).unwrap(),
    ));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));

    for &variant in RING_BUF_VARIANTS {
        for (name, mode) in [("next", Mode::Next), ("drain", Mode::Drain)] {
            group.bench_with_input(BenchmarkId::new(name, variant.prog), &variant, |b, &variant| {
                let mut bench = RingBufBench::new(variant);
                b.iter_custom(|iters| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iters {
                        let (seen, t) = run_overlap(&mut bench, mode, EVENTS_PER_ITER);
                        assert_eq!(seen, EVENTS_PER_ITER);
                        elapsed += t;
                    }
                    elapsed
                });
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_ring_buf_next_vs_drain_epoll);
criterion_main!(benches);
