use std::num::NonZeroU64;

use aya::{
    EbpfLoader,
    maps::{Array, HashMap, MapType, PerCpuHashMap, PerCpuValues},
    programs::{UProbe, uprobe::UProbeScope},
    sys::is_map_supported,
    util::nr_cpus,
};
use rstest::rstest;

const EXPECTED: u64 = 42;

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_hash_lookup() {
    std::hint::black_box(());
}

#[rstest]
#[case::hash_btf(MapType::Hash, "test_hash_btf", "HASH_BTF", "RESULT")]
#[case::lru_hash_btf(MapType::LruHash, "test_lru_hash_btf", "LRU_HASH_BTF", "RESULT")]
#[case::per_cpu_hash_btf(
    MapType::PerCpuHash,
    "test_per_cpu_hash_btf",
    "PER_CPU_HASH_BTF",
    "RESULT"
)]
#[case::lru_per_cpu_hash_btf(
    MapType::LruPerCpuHash,
    "test_lru_per_cpu_hash_btf",
    "LRU_PER_CPU_HASH_BTF",
    "RESULT"
)]
#[case::hash_legacy(MapType::Hash, "test_hash_legacy", "HASH_LEGACY", "RESULT_LEGACY")]
#[case::lru_hash_legacy(
    MapType::LruHash,
    "test_lru_hash_legacy",
    "LRU_HASH_LEGACY",
    "RESULT_LEGACY"
)]
#[case::per_cpu_hash_legacy(
    MapType::PerCpuHash,
    "test_per_cpu_hash_legacy",
    "PER_CPU_HASH_LEGACY",
    "RESULT_LEGACY"
)]
#[case::lru_per_cpu_hash_legacy(
    MapType::LruPerCpuHash,
    "test_lru_per_cpu_hash_legacy",
    "LRU_PER_CPU_HASH_LEGACY",
    "RESULT_LEGACY"
)]
#[test_attr(test_log::test)]
fn hash_basic(
    #[case] map_type: MapType,
    #[case] prog_name: &str,
    #[case] map_name: &str,
    #[case] result_map: &str,
) {
    if matches!(map_type, MapType::LruHash | MapType::LruPerCpuHash)
        && !is_map_supported(map_type).unwrap()
    {
        eprintln!("skipping test - {map_type:?} not supported");
        return;
    }
    let mut bpf = EbpfLoader::new().load(crate::HASH_MAP).unwrap();
    let per_cpu_range =
        matches!(map_type, MapType::PerCpuHash | MapType::LruPerCpuHash).then(|| {
            let count = NonZeroU64::from(nr_cpus().unwrap());
            EXPECTED..EXPECTED + count.get()
        });

    if let Some(range) = &per_cpu_range {
        let mut map: PerCpuHashMap<_, u32, u64> =
            bpf.map_mut(map_name).unwrap().try_into().unwrap();
        // Distinct value per CPU exercises per-CPU divergence: the
        // kernel must keep slots independent across CPUs.
        let expected_per_cpu: Vec<u64> = range.clone().collect();
        map.insert(
            &0u32,
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
        map.insert(&0u32, &EXPECTED, 0).unwrap();
    }

    let prog: &mut UProbe = bpf.program_mut(prog_name).unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach(
        ["trigger_hash_lookup"],
        "/proc/self/exe",
        UProbeScope::AllProcesses,
    )
    .unwrap();

    trigger_hash_lookup();

    let result: Array<_, u64> = bpf.map(result_map).unwrap().try_into().unwrap();
    let observed = result.get(&0, 0).unwrap();
    if let Some(range) = per_cpu_range {
        assert!(
            range.contains(&observed),
            "per-CPU read {observed} not in {range:?}",
        );
    } else {
        assert_eq!(observed, EXPECTED);
    }
}
