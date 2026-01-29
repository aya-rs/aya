#![expect(
    clippy::self_named_module_files,
    reason = "the test harness uses a flat tests module"
)]
#![expect(clippy::print_stderr, reason = "integration tests print skip reasons")]
#![expect(
    clippy::use_debug,
    reason = "debug formatting aids diagnostics in tests"
)]

mod array;
mod bpf_probe_read;
mod btf_maps;
mod btf_relocations;
mod elf;
mod feature_probe;
mod info;
mod iter;
mod linear_data_structures;
mod load;
mod log;
mod lsm;
mod map_of_maps;
mod map_pin;
mod maps_disjoint;
mod perf_event_bp;
mod prog_array;
mod raw_tracepoint;
mod rbpf;
mod relocations;
mod ring_buf;
mod sk_storage;
mod smoke;
mod strncmp;
mod tcx;
mod uprobe_cookie;
mod xdp;
