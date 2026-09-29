#![expect(
    clippy::self_named_module_files,
    reason = "the test harness uses a flat tests module"
)]
#![expect(clippy::print_stderr, reason = "integration tests print skip reasons")]
#![expect(
    clippy::use_debug,
    reason = "debug formatting aids diagnostics in tests"
)]

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use aya::test_helpers::{NetNsGuard, with_tracefs_probes};

fn run_netns_tokio<F, Fut, T>(test: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    let _netns = NetNsGuard::new().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(test())
}

fn check_tracefs_cleanup<L>(pmu: &str, count: usize, attach: impl FnOnce() -> L, finish: fn(L)) {
    fn events(path: &Path) -> HashSet<String> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    // Serialize these cases because tracefs registrations are shared across threads.
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let tracefs = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.join(format!("{pmu}_events")).try_exists().unwrap())
        .unwrap();
    let events_path = tracefs.join(format!("{pmu}_events"));
    let before = events(&events_path);
    let link = with_tracefs_probes(attach);
    let attached = events(&events_path);
    let added: Vec<_> = attached.difference(&before).collect();
    assert_eq!(added.len(), count);
    let event_paths: Vec<_> = added
        .iter()
        .map(|event| {
            // E.g. `p:uprobes/aya_probe /proc/self/exe:0x1234` yields
            // `uprobes/aya_probe`, relative to the tracefs `events/` directory.
            let (_, name) = event
                .split_whitespace()
                .next()
                .unwrap()
                .split_once(':')
                .unwrap();
            let path = tracefs.join("events").join(name);
            assert!(path.try_exists().unwrap(), "missing event: {event}");
            path
        })
        .collect();

    // Run detach, drop, or the rejected conversion before checking the registrations.
    finish(link);

    let remaining = events(&events_path);
    for (event, path) in added.into_iter().zip(event_paths) {
        assert!(
            !remaining.contains(event),
            "event still registered: {event}"
        );
        assert!(
            !path.try_exists().unwrap(),
            "event directory remains: {event}"
        );
    }
}

mod array;
mod bloom_filter;
mod bpf_probe_read;
mod btf_map_of_maps;
mod btf_maps;
mod btf_relocations;
mod cgroup_array;
mod cgroup_storage;
mod cgrp_storage;
mod elf;
mod feature_probe;
mod fexit;
mod hash_map;
mod info;
mod inode_storage;
mod iter;
mod kprobe;
mod ksyms;
mod linear_data_structures;
mod load;
mod log;
mod lpm_trie;
mod lsm;
mod map_pin;
mod maps_disjoint;
mod per_cpu_array;
mod perf_event_array;
mod perf_event_bp;
mod printk;
mod prog_array;
mod prog_test_run;
mod raw_tracepoint;
mod rbpf;
mod relocations;
mod ring_buf;
mod sk_lookup;
mod sk_reuseport;
mod sk_storage;
mod smoke;
mod sock_map;
mod socket_filter;
mod stack_trace;
mod stack_trace_lsm;
mod strncmp;
mod tc_classid;
mod tc_netlink;
mod tcx;
mod uprobe_cookie;
mod uprobe_multi;
mod xdp;
