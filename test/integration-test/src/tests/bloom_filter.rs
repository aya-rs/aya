use aya::{
    EbpfLoader,
    maps::{Array, BloomFilter},
    programs::UProbe, util::KernelVersion,
};

#[test_log::test]
fn test_bloom_filter() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 16, 0) {
        eprintln!("skipping tcx_attach test on kernel {kernel_version:?}");
        return;
    }

    let mut ebpf = EbpfLoader::new().load(crate::BLOOM_FILTER).unwrap();

    // Test 1: Insert from userspace, check from userspace
    {
        let bloom = ebpf.map_mut("BLOOM").unwrap();
        let mut bloom_filter = BloomFilter::<_, u32>::try_from(bloom).unwrap();
        bloom_filter.insert(42, 0).unwrap();
        assert!(
            bloom_filter.contains(&42, 0).is_ok(),
            "userspace->userspace: value 42 should exist"
        );
        assert!(
            bloom_filter.contains(&99, 0).is_err(),
            "userspace->userspace: value 99 should not exist"
        );
    }
}
