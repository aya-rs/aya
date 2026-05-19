use aya::{
    EbpfLoader,
    maps::{Array, HashMap, MapType, PerCpuHashMap, PerCpuValues},
    programs::{UProbe, uprobe::UProbeScope},
    sys::is_map_supported,
    util::nr_cpus,
};
use test_case::test_case;

const EXPECTED: u64 = 42;

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_hash_lookup() {
    std::hint::black_box(());
}

#[test_log::test(test_case(MapType::Hash, "test_hash_btf", "HASH_BTF", "RESULT" ; "hash_btf"))]
#[test_case(MapType::LruHash, "test_lru_hash_btf", "LRU_HASH_BTF", "RESULT" ; "lru_hash_btf")]
#[test_case(MapType::PerCpuHash, "test_per_cpu_hash_btf", "PER_CPU_HASH_BTF", "RESULT" ; "per_cpu_hash_btf")]
#[test_case(MapType::LruPerCpuHash, "test_lru_per_cpu_hash_btf", "LRU_PER_CPU_HASH_BTF", "RESULT" ; "lru_per_cpu_hash_btf")]
#[test_case(MapType::Hash, "test_hash_legacy", "HASH_LEGACY", "RESULT_LEGACY" ; "hash_legacy")]
#[test_case(MapType::LruHash, "test_lru_hash_legacy", "LRU_HASH_LEGACY", "RESULT_LEGACY" ; "lru_hash_legacy")]
#[test_case(MapType::PerCpuHash, "test_per_cpu_hash_legacy", "PER_CPU_HASH_LEGACY", "RESULT_LEGACY" ; "per_cpu_hash_legacy")]
#[test_case(MapType::LruPerCpuHash, "test_lru_per_cpu_hash_legacy", "LRU_PER_CPU_HASH_LEGACY", "RESULT_LEGACY" ; "lru_per_cpu_hash_legacy")]
fn hash_basic(map_type: MapType, prog_name: &str, map_name: &str, result_map: &str) {
    if matches!(map_type, MapType::LruHash | MapType::LruPerCpuHash)
        && !is_map_supported(map_type).unwrap()
    {
        eprintln!("skipping test - {map_type:?} not supported");
        return;
    }
    let per_cpu = matches!(map_type, MapType::PerCpuHash | MapType::LruPerCpuHash);
    let mut bpf = EbpfLoader::new().load(crate::HASH_MAP).unwrap();

    if per_cpu {
        let mut map: PerCpuHashMap<_, u32, u64> =
            bpf.map_mut(map_name).unwrap().try_into().unwrap();
        // Distinct value per CPU exercises per-CPU divergence: the
        // kernel must keep slots independent across CPUs.
        let expected_per_cpu: Vec<u64> = (0..nr_cpus().unwrap())
            .map(|i| EXPECTED + i as u64)
            .collect();
        map.insert(
            0u32,
            PerCpuValues::try_from(expected_per_cpu.clone()).unwrap(),
            0,
        )
        .unwrap();
        let readback = map.get(&0u32, 0).unwrap();
        for (cpu, slot) in readback.iter().enumerate() {
            assert_eq!(*slot, expected_per_cpu[cpu], "per-CPU slot {cpu}");
        }
    } else {
        let mut map: HashMap<_, u32, u64> = bpf.map_mut(map_name).unwrap().try_into().unwrap();
        map.insert(0u32, EXPECTED, 0).unwrap();
    }

    let prog: &mut UProbe = bpf.program_mut(prog_name).unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach(
        "trigger_hash_lookup",
        "/proc/self/exe",
        UProbeScope::AllProcesses,
    )
    .unwrap();

    trigger_hash_lookup();

    let result: Array<_, u64> = bpf.map(result_map).unwrap().try_into().unwrap();
    let observed = result.get(&0, 0).unwrap();
    if per_cpu {
        let range = EXPECTED..EXPECTED + nr_cpus().unwrap() as u64;
        assert!(
            range.contains(&observed),
            "per-CPU read {observed} not in {range:?}",
        );
    } else {
        assert_eq!(observed, EXPECTED);
    }
}
