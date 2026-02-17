#![expect(unused_crate_dependencies, reason = "used in tests")]

use std::{
    hint::black_box,
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
const PREFILL_ITEMS: usize = RING_BUF_MAX_ENTRIES - 1;

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

const ALL_RING_BUFS: &[&str] = &["RING_BUF", "RING_BUF_LEGACY", "RING_BUF_MISMATCH"];

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

    fn assert_no_rejections(&self) {
        let Registers { rejected, .. } = self.registers();
        assert_eq!(rejected, 0);
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
const extern "C" fn ring_buf_trigger_ebpf_program(arg: u64) {
    black_box(arg);
}

fn drain_unbatched_target(ring_buf: &mut RingBuf<MapData>, target: usize) -> usize {
    let mut seen = 0;
    while let Some(item) = ring_buf.next() {
        let _: [u8; 8] = (*item).try_into().unwrap();
        seen += 1;
        if seen >= target {
            break;
        }
    }
    seen
}

fn drain_batched_target(ring_buf: &mut RingBuf<MapData>, target: usize) -> usize {
    let mut seen = 0;
    let mut batch = ring_buf.batch();
    while let Some(item) = batch.next() {
        let _: [u8; 8] = (*item).try_into().unwrap();
        seen += 1;
        if seen >= target {
            break;
        }
    }
    seen
}

fn drain_unbatched_all(ring_buf: &mut RingBuf<MapData>) {
    while let Some(item) = ring_buf.next() {
        let _: [u8; 8] = (*item).try_into().unwrap();
    }
}

fn prefill(seq: &mut u64, target: usize) {
    for _ in 0..target {
        // Keep values even so the eBPF program doesn't reject them.
        ring_buf_trigger_ebpf_program(*seq * 2);
        *seq += 1;
    }
}

fn bench_ring_buf(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buf/drain_prefilled");
    group.throughput(criterion::Throughput::Elements(
        u64::try_from(PREFILL_ITEMS).unwrap(),
    ));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));

    for &variant in RING_BUF_VARIANTS {
        group.bench_with_input(
            BenchmarkId::new("unbatched", variant.prog),
            &variant,
            |b, &variant| {
                let mut bench = RingBufBench::new(variant);
                let mut seq = 0u64;
                b.iter_custom(|iters| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iters {
                        drain_unbatched_all(&mut bench.ring_buf);
                        let before = bench.registers();
                        prefill(&mut seq, PREFILL_ITEMS);
                        let start = Instant::now();
                        let seen = drain_unbatched_target(&mut bench.ring_buf, PREFILL_ITEMS);
                        elapsed += start.elapsed();
                        assert_eq!(seen, PREFILL_ITEMS);
                        let after = bench.registers();
                        assert_eq!(after.dropped, before.dropped);
                        assert_eq!(after.rejected, before.rejected);
                    }
                    elapsed
                });
                bench.assert_no_rejections();
            },
        );

        group.bench_with_input(
            BenchmarkId::new("batched", variant.prog),
            &variant,
            |b, &variant| {
                let mut bench = RingBufBench::new(variant);
                let mut seq = 0u64;
                b.iter_custom(|iters| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iters {
                        drain_unbatched_all(&mut bench.ring_buf);
                        let before = bench.registers();
                        prefill(&mut seq, PREFILL_ITEMS);
                        let start = Instant::now();
                        let seen = drain_batched_target(&mut bench.ring_buf, PREFILL_ITEMS);
                        elapsed += start.elapsed();
                        assert_eq!(seen, PREFILL_ITEMS);
                        let after = bench.registers();
                        assert_eq!(after.dropped, before.dropped);
                        assert_eq!(after.rejected, before.rejected);
                    }
                    elapsed
                });
                bench.assert_no_rejections();
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_ring_buf);
criterion_main!(benches);
