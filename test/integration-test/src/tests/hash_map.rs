use std::thread;

use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, HashMap, MapData, MapError, PerCpuHashMap},
    programs::UProbe,
};
use integration_common::hash_map::GET_INDEX;

/// Triggers the eBPF program that inserts the given `key` and `value` pair
/// into the hash map.
#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn hash_map_insert(key: u32, value: u32) {
    std::hint::black_box((key, value));
}

/// Triggers the eBPF program that retrieves the value associated with the
/// `key` and inserts it into the array.
#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn hash_map_get(key: u32) {
    std::hint::black_box(key);
}

/// Loads the uprobe program and attaches it to the given `symbol`.
fn load_program(ebpf: &mut Ebpf, prog_name: &str, symbol: &str) {
    let prog: &mut UProbe = ebpf.program_mut(prog_name).unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach(symbol, "/proc/self/exe", None, None).unwrap();
}

/// Loads the pair of programs:
///
/// * `insert_prog` that inserts key and value pairs into the `hash_map`.
/// * `get_prog` that retrieves values from the `hash_map` and inserts them
///   into `result_map`.
///
/// Returns the result array and the hash map.
fn load_programs_with_maps<'a>(
    ebpf: &'a mut Ebpf,
    result_array: &'a str,
    hash_map: &'a str,
    insert_prog: &'a str,
    get_prog: &'a str,
) -> (Array<&'a MapData, u32>, HashMap<&'a MapData, u32, u32>) {
    load_program(ebpf, insert_prog, "hash_map_insert");
    load_program(ebpf, get_prog, "hash_map_get");

    let result_array = ebpf.map(result_array).unwrap();
    let result_array = Array::<_, u32>::try_from(result_array).unwrap();

    let hash_map = ebpf.map(hash_map).unwrap();
    let hash_map = HashMap::<_, u32, u32>::try_from(hash_map).unwrap();

    (result_array, hash_map)
}

/// Loads the `insert_prog` program that inserts elements into the
/// `per_cpu_hash_map`. Returns the map.
fn load_program_with_per_cpu_map<'a>(
    ebpf: &'a mut Ebpf,
    per_cpu_hash_map: &'a str,
    insert_prog: &'a str,
) -> PerCpuHashMap<&'a MapData, u32, u32> {
    load_program(ebpf, insert_prog, "hash_map_insert");

    let hash_map = ebpf.map(per_cpu_hash_map).unwrap();
    PerCpuHashMap::<_, u32, u32>::try_from(hash_map).unwrap()
}

#[test_log::test]
fn test_hash_map() {
    let mut ebpf = EbpfLoader::new().load(crate::HASH_MAP).unwrap();
    for (result_map_name, hash_map_name, insert_prog_name, get_prog_name) in [
        // BTF map definitions.
        ("RESULT", "HASH_MAP", "hash_map_insert", "hash_map_get"),
        // Legacy map definitions.
        (
            "RESULT_LEGACY",
            "HASH_MAP_LEGACY",
            "hash_map_insert_legacy",
            "hash_map_get_legacy",
        ),
    ] {
        let (result_array, hash_map) = load_programs_with_maps(
            &mut ebpf,
            result_map_name,
            hash_map_name,
            insert_prog_name,
            get_prog_name,
        );

        let seq = 0_u32..9;
        for i in seq.clone() {
            hash_map_insert(i.pow(2), i);
        }
        for i in seq.clone() {
            // Assert the value returned by user-space API.
            let key = i.pow(2);
            let value = hash_map.get(&key, 0).unwrap();
            assert_eq!(value, i);
            // Assert the value returned by eBPF in-kernel API.
            hash_map_get(key);
            let result = result_array.get(&GET_INDEX, 0).unwrap();
            assert_eq!(result, i);
        }
    }
}

#[test_log::test]
fn test_lru_hash_map() {
    let mut ebpf = EbpfLoader::new().load(crate::HASH_MAP).unwrap();
    for (result_map_name, hash_map_name, insert_prog_name, get_prog_name) in [
        // BTF map definitions.
        (
            "RESULT",
            "LRU_HASH_MAP",
            "lru_hash_map_insert",
            "lru_hash_map_get",
        ),
        // Legacy map definitions.
        (
            "RESULT_LEGACY",
            "LRU_HASH_MAP_LEGACY",
            "lru_hash_map_insert_legacy",
            "lru_hash_map_get_legacy",
        ),
    ] {
        let (result_array, hash_map) = load_programs_with_maps(
            &mut ebpf,
            result_map_name,
            hash_map_name,
            insert_prog_name,
            get_prog_name,
        );

        // Insert elements over capacity.
        let seq = 0_u32..15;
        for i in seq.clone() {
            hash_map_insert(i.pow(2), i);
        }
        // Check whether elements 0..5 got evicted.
        for i in 0_u32..5 {
            let key = i.pow(2);
            assert!(matches!(hash_map.get(&key, 0), Err(MapError::KeyNotFound)));
        }
        // Check whether the newest 10 elements can be retrieved.
        for i in 5_u32..15 {
            // Assert the value returned by user-space API.
            let key = i.pow(2);
            let value = hash_map.get(&key, 0).unwrap();
            assert_eq!(value, i);
            // Assert the value returned by eBPF in-kernel API.
            hash_map_get(key);
            let result = result_array.get(&GET_INDEX, 0).unwrap();
            assert_eq!(result, i);
        }
    }
}

#[test_log::test]
fn test_per_cpu_hash_map() {
    let mut ebpf = EbpfLoader::new().load(crate::HASH_MAP).unwrap();
    for (hash_map_name, insert_prog_name) in [
        // BTF map definitions.
        ("PER_CPU_HASH_MAP", "per_cpu_hash_map_insert"),
        // Legacy map definitions.
        ("PER_CPU_HASH_MAP_LEGACY", "per_cpu_hash_map_insert_legacy"),
    ] {
        let hash_map = load_program_with_per_cpu_map(&mut ebpf, hash_map_name, insert_prog_name);

        let seq = 0_u32..9;
        thread::scope(|s| {
            let seq = seq.clone();
            s.spawn(move || {
                let mut cpu_set = nix::sched::CpuSet::new();
                cpu_set.set(0).unwrap();
                nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &cpu_set).unwrap();

                for i in seq {
                    hash_map_insert(i.pow(2), i);
                }
            });
        });
        for i in seq.clone() {
            let key = i.pow(2);
            let values = hash_map.get(&key, 0).unwrap();
            assert_eq!(values.first().unwrap(), &i);
        }
    }
}

#[test_log::test]
fn test_lru_per_cpu_hash_map() {
    let mut ebpf = EbpfLoader::new().load(crate::HASH_MAP).unwrap();
    for (hash_map_name, insert_prog_name) in [
        // BTF map definitions.
        ("LRU_PER_CPU_HASH_MAP", "lru_per_cpu_hash_map_insert"),
        // Legacy map definitions.
        (
            "LRU_PER_CPU_HASH_MAP_LEGACY",
            "lru_per_cpu_hash_map_insert_legacy",
        ),
    ] {
        let hash_map = load_program_with_per_cpu_map(&mut ebpf, hash_map_name, insert_prog_name);

        // Insert elements over capacity.
        let seq = 0_u32..15;
        thread::scope(|s| {
            let seq = seq.clone();
            s.spawn(move || {
                let mut cpu_set = nix::sched::CpuSet::new();
                cpu_set.set(0).unwrap();
                nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &cpu_set).unwrap();

                for i in seq {
                    hash_map_insert(i.pow(2), i);
                }
            });
        });
        // Check whether elements 0..5 got evicted.
        for i in 0_u32..5 {
            let key = i.pow(2);
            assert!(matches!(hash_map.get(&key, 0), Err(MapError::KeyNotFound)));
        }
        // Check whether the newest 10 elements can be retrieved.
        for i in 5_u32..15 {
            let key = i.pow(2);
            let values = hash_map.get(&key, 0).unwrap();
            assert_eq!(values.first().unwrap(), &i);
        }
    }
}
