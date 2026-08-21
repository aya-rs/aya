//! Tests for BPF arena maps: memory shared between userspace and BPF.

use std::{path::Path, sync::atomic::Ordering};

use aya::{
    Ebpf, EbpfLoader, TestRunOptions,
    maps::{Arena, Array, MapData, MapType},
    programs::{TestRun as _, UProbe, Xdp, uprobe::UProbeScope},
    sys::is_map_supported,
};
use aya_obj::{
    Object,
    generated::{BPF_DW, BPF_IMM, BPF_LD, BPF_PSEUDO_MAP_VALUE},
};
use integration_common::arena::{Node, Root};
use rand::RngExt as _;
use scopeguard::defer;

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn arena_trigger_ebpf_program() {
    std::hint::black_box(());
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn arena_trigger_atomic_program() {
    std::hint::black_box(());
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn arena_trigger_pages_program() {
    std::hint::black_box(());
}

#[test]
fn arena_globals_relocations() {
    const ARENA_FD: i32 = 12;

    let mut object = Object::parse(crate::ARENA_LOADER).unwrap();
    object
        .maps
        .get_mut("arena")
        .unwrap()
        .arena_data_mut()
        .unwrap()
        .set_map_offset(0x1000);
    let maps = object.maps.clone();
    let text_sections = object
        .functions
        .keys()
        .map(|(section_index, _)| *section_index)
        .collect();

    object
        .relocate_maps(
            maps.iter()
                .map(|(name, map)| (name.as_str(), ARENA_FD, map)),
            &text_sections,
        )
        .unwrap();

    let program = &object.programs["arena_globals"];
    let function = &object.functions[&program.function_key()];
    let mut offsets = function
        .instructions
        .windows(2)
        .filter_map(|instructions| match instructions {
            [first, second]
                if first.code == (BPF_LD | BPF_DW | BPF_IMM) as u8
                    && first.src_reg() == BPF_PSEUDO_MAP_VALUE as u8 =>
            {
                assert_eq!(first.imm, ARENA_FD);
                Some(second.imm)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    offsets.sort_unstable();

    assert_eq!(offsets, [0x1000, 0x1008]);
}

fn load_arena_loader(pin_path: Option<&Path>) -> Ebpf {
    let mut loader = EbpfLoader::new();
    loader.map_max_entries("arena", 4);
    if let Some(pin_path) = pin_path {
        loader.map_pin_path("arena", pin_path);
    }
    loader.load(crate::ARENA_LOADER).unwrap()
}

fn page_size() -> usize {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(page_size > 0);
    page_size as usize
}

fn arena_globals_data_offset(arena: &Arena<MapData>) -> usize {
    if aya::features().ldimm64_full_range_offset() {
        arena.len() - page_size()
    } else {
        0
    }
}

fn arena_globals_values(arena: &Arena<MapData>) -> (u64, u64) {
    let offset = arena_globals_data_offset(arena);
    unsafe {
        (
            arena.read_at(offset).unwrap(),
            arena.read_at(offset + size_of::<u64>()).unwrap(),
        )
    }
}

fn run_arena_globals(bpf: &mut Ebpf) {
    let prog: &mut Xdp = bpf
        .program_mut("arena_globals")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let data_in = [0; 64];
    let mut data_out = [0; 64];
    let result = prog
        .test_run(TestRunOptions {
            data_in: Some(&data_in),
            data_out: Some(&mut data_out),
            ..TestRunOptions::default()
        })
        .unwrap();
    assert_eq!(result.return_value, 2); // XDP_PASS
}

#[test_log::test]
fn arena_globals_load_and_initialize() {
    if !is_map_supported(MapType::Arena).unwrap() {
        eprintln!("skipping test - arena map not supported");
        return;
    }

    let mut bpf = load_arena_loader(None);
    let arena = Arena::try_from(bpf.take_map("arena").unwrap()).unwrap();

    assert_eq!(arena.len(), 4 * page_size());
    assert_eq!(arena_globals_values(&arena), (5, 10));

    run_arena_globals(&mut bpf);
    assert_eq!(arena_globals_values(&arena), (15, 11));
}

#[test_log::test]
fn arena_globals_reuse_preserves_contents() {
    if !is_map_supported(MapType::Arena).unwrap() {
        eprintln!("skipping test - arena map not supported");
        return;
    }

    let pin_path = Path::new("/sys/fs/bpf").join(format!(
        "aya_arena_globals_{:x}",
        rand::rng().random::<u64>()
    ));

    let mut bpf = load_arena_loader(Some(&pin_path));
    defer! { std::fs::remove_file(&pin_path).unwrap() }
    let arena = Arena::try_from(bpf.take_map("arena").unwrap()).unwrap();
    run_arena_globals(&mut bpf);
    assert_eq!(arena_globals_values(&arena), (15, 11));
    drop(arena);
    drop(bpf);

    let mut bpf = load_arena_loader(Some(&pin_path));
    let arena = Arena::try_from(bpf.take_map("arena").unwrap()).unwrap();
    assert_eq!(arena_globals_values(&arena), (15, 11));

    run_arena_globals(&mut bpf);
    assert_eq!(arena_globals_values(&arena), (26, 12));
}

#[test_log::test]
fn arena_page_lifecycle_and_faults() {
    if !is_map_supported(MapType::Arena).unwrap() {
        eprintln!("skipping test - arena map not supported");
        return;
    }

    const COMMAND: u32 = 0;
    const ADDRESS: u32 = 1;
    const INITIAL_VALUE: u32 = 2;
    const VALUE_BEFORE_FREE: u32 = 3;
    const VALUE_AFTER_FREE: u32 = 4;
    const VALUE_AFTER_WRITE: u32 = 5;

    const ALLOCATE: u64 = 1;
    const FREE: u64 = 2;
    const PROBE_ACCESS: u64 = 3;

    const TEST_VALUE: u64 = 0x0123_4567_89ab_cdef;

    let mut bpf = load_arena_loader(None);
    let arena = Arena::try_from(bpf.take_map("arena").unwrap()).unwrap();
    let mut results: Array<_, u64> =
        Array::try_from(bpf.take_map("arena_results").unwrap()).unwrap();

    let prog: &mut UProbe = bpf.program_mut("arena_pages").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach(
        ["arena_trigger_pages_program"],
        "/proc/self/exe",
        UProbeScope::AllProcesses,
    )
    .unwrap();

    results.set(COMMAND, &ALLOCATE, 0).unwrap();
    arena_trigger_pages_program();

    let address = results.get(&ADDRESS, 0).unwrap();
    let offset = usize::try_from(address.checked_sub(arena.user_base()).unwrap()).unwrap();
    assert!(offset < arena.len());
    assert!(offset.is_multiple_of(page_size()));
    assert_eq!(results.get(&INITIAL_VALUE, 0).unwrap(), 0);
    assert_eq!(unsafe { arena.read_at::<u64>(offset).unwrap() }, TEST_VALUE);

    results.set(COMMAND, &FREE, 0).unwrap();
    arena_trigger_pages_program();

    assert_eq!(results.get(&VALUE_BEFORE_FREE, 0).unwrap(), TEST_VALUE);
    assert_eq!(results.get(&VALUE_AFTER_FREE, 0).unwrap(), 0);

    // BPF accesses to an unallocated arena page are fault-contained: loads
    // return zero and stores are skipped.
    results.set(COMMAND, &PROBE_ACCESS, 0).unwrap();
    arena_trigger_pages_program();
    assert_eq!(results.get(&INITIAL_VALUE, 0).unwrap(), 0);
    assert_eq!(results.get(&VALUE_AFTER_WRITE, 0).unwrap(), 0);

    // The same contract applies just beyond the arena's addressable range.
    let address = arena.user_base() + arena.len() as u64;
    results.set(ADDRESS, &address, 0).unwrap();
    arena_trigger_pages_program();
    assert_eq!(results.get(&INITIAL_VALUE, 0).unwrap(), 0);
    assert_eq!(results.get(&VALUE_AFTER_WRITE, 0).unwrap(), 0);
}

/// Userspace builds a linked list in the arena; the BPF program walks it
/// (re-blessing every pointer loaded from arena memory with
/// `addr_space_cast`), sums and doubles the node values, and bumps a counter.
///
/// The arena's user mapping lives at an arbitrary base address, so the root
/// object's address is communicated to the BPF program through a regular
/// array map.
#[test_log::test]
fn arena_shared_list() {
    if !is_map_supported(MapType::Arena).unwrap() {
        eprintln!("skipping test - arena map not supported");
        return;
    }

    let mut bpf = Ebpf::load(crate::ARENA).unwrap();
    let map = bpf.take_map("ARENA").unwrap();
    let arena = Arena::try_from(map).unwrap();

    // Build a 3-node list on the second arena page, linked by user-space
    // virtual addresses (what the BPF-side ArenaPtr expects).
    let base = arena.user_base();
    let (n1, n2, n3) = (0x1000, 0x1040, 0x1080);
    unsafe {
        arena.write_at(n3, Node { value: 3, next: 0 }).unwrap();
        arena
            .write_at(
                n2,
                Node {
                    value: 2,
                    next: base + n3 as u64,
                },
            )
            .unwrap();
        arena
            .write_at(
                n1,
                Node {
                    value: 1,
                    next: base + n2 as u64,
                },
            )
            .unwrap();
        arena
            .write_at(
                0,
                Root {
                    counter: 0,
                    sum: 0,
                    head: base + n1 as u64,
                },
            )
            .unwrap();
    }

    // Anchor: tell the BPF program where the root object lives.
    let mut root_ptr: Array<_, u64> = Array::try_from(bpf.map_mut("ROOT_PTR").unwrap()).unwrap();
    root_ptr.set(0, &base, 0).unwrap();

    let prog: &mut UProbe = bpf.program_mut("arena_test").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach(
        ["arena_trigger_ebpf_program"],
        "/proc/self/exe",
        UProbeScope::AllProcesses,
    )
    .unwrap();

    arena_trigger_ebpf_program();

    let root: Root = unsafe { arena.read_at(0).unwrap() };
    assert_eq!(root.counter, 1);
    assert_eq!(root.sum, 1 + 2 + 3);
    assert_eq!(unsafe { arena.read_at::<Node>(n1).unwrap() }.value, 2);
    assert_eq!(unsafe { arena.read_at::<Node>(n2).unwrap() }.value, 4);
    assert_eq!(unsafe { arena.read_at::<Node>(n3).unwrap() }.value, 6);

    // Second trigger: the list values double again.
    arena_trigger_ebpf_program();
    let root: Root = unsafe { arena.read_at(0).unwrap() };
    assert_eq!(root.counter, 2);
    assert_eq!(root.sum, 2 + 4 + 6);
}

#[test_log::test]
fn arena_atomic_counter() {
    if !is_map_supported(MapType::Arena).unwrap() {
        eprintln!("skipping test - arena map not supported");
        return;
    }

    let mut bpf = Ebpf::load(crate::ARENA).unwrap();
    let map = bpf.take_map("ARENA").unwrap();
    let arena = Arena::try_from(map).unwrap();
    let counter = unsafe { arena.atomic_u64_at(0).unwrap() };
    counter.store(0, Ordering::Relaxed);

    let mut root_ptr: Array<_, u64> = Array::try_from(bpf.map_mut("ROOT_PTR").unwrap()).unwrap();
    let base = arena.user_base();
    root_ptr.set(0, &base, 0).unwrap();

    let prog: &mut UProbe = bpf.program_mut("arena_atomic").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach(
        ["arena_trigger_atomic_program"],
        "/proc/self/exe",
        UProbeScope::AllProcesses,
    )
    .unwrap();

    const THREADS: u64 = 4;
    const INCREMENTS: u64 = 100;
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                for _ in 0..INCREMENTS {
                    arena_trigger_atomic_program();
                }
            });
        }
        for _ in 0..THREADS * INCREMENTS {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });

    assert_eq!(counter.load(Ordering::Relaxed), THREADS * INCREMENTS * 2);
}
