#![allow(unused_crate_dependencies)]

use std::{mem, ptr};

use aya::maps::perf::bench::{BenchBuffer, default_page_size};
use aya_obj::generated::{perf_event_header, perf_event_type::PERF_RECORD_SAMPLE};
use bytes::BytesMut;
use criterion::{Throughput, black_box, criterion_group, criterion_main, Criterion};

fn write<T: Copy>(buf: &mut BenchBuffer, offset: usize, value: T) -> usize {
    let dst = buf.data_mut().as_mut_ptr();
    let head = offset + mem::size_of::<T>();
    unsafe {
        ptr::write_unaligned(dst.add(offset).cast(), value);
        buf.mmap_page_mut().data_head = head as u64;
    }
    head
}

fn write_sample(buf: &mut BenchBuffer, offset: usize, sample_size: usize) -> usize {
    let header = perf_event_header {
        type_: PERF_RECORD_SAMPLE as u32,
        misc: 0,
        size: (mem::size_of::<perf_event_header>() + mem::size_of::<u32>() + sample_size) as u16,
    };
    let start = write(buf, offset, header);
    let start = write(buf, start, sample_size as u32);
    unsafe {
        let dst = buf.data_mut().as_mut_ptr().add(start);
        ptr::write_bytes(dst, 0xAB, sample_size);
    }
    let head = start + sample_size;
    buf.mmap_page_mut().data_head = head as u64;
    head
}

fn fill_samples(buf: &mut BenchBuffer, events: usize, sample_size: usize) -> usize {
    let mut offset = 0;
    for _ in 0..events {
        offset = write_sample(buf, offset, sample_size);
    }
    buf.mmap_page_mut().data_tail = 0;
    offset
}

fn bench_perf_buffer(c: &mut Criterion) {
    let page_size = default_page_size();
    let sample_sizes = [64, 256, 1024, 4096];
    let page_counts = [1usize, 8, 32];

    let mut group = c.benchmark_group("perf_buffer");
    for &sample_size in &sample_sizes {
        for &page_count in &page_counts {
            let mut bench = BenchBuffer::new(page_size, page_count).unwrap();
            let ring_size = page_size * page_count;
            let event_size =
                mem::size_of::<perf_event_header>() + mem::size_of::<u32>() + sample_size;
            if event_size > ring_size {
                continue;
            }
            let events = (ring_size / event_size).max(1);
            fill_samples(&mut bench, events, sample_size);

            let mut out_bufs = (0..events)
                .map(|_| BytesMut::with_capacity(sample_size))
                .collect::<Vec<_>>();

            group.throughput(Throughput::Bytes((events * sample_size) as u64));
            group.bench_function(
                format!("copy/size{}_pages{}", sample_size, page_count),
                |b| {
                    b.iter(|| {
                        bench.mmap_page_mut().data_tail = 0;
                        let result = bench.read_events(&mut out_bufs).unwrap();
                        black_box(result);
                        black_box(&out_bufs);
                    })
                },
            );

            group.bench_function(
                format!("raw/size{}_pages{}", sample_size, page_count),
                |b| {
                    b.iter(|| {
                        bench.mmap_page_mut().data_tail = 0;
                        let raw = bench.read_events_raw().unwrap();
                        let mut total = 0usize;
                        for sample in raw {
                            let (first, second) = sample.data().as_slices();
                            total += first.len() + second.len();
                        }
                        black_box(total);
                    })
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_perf_buffer);
criterion_main!(benches);
