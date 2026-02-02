use aya::{
    EbpfLoader,
    maps::{Array, BloomFilter},
    programs::UProbe,
};

#[test_log::test]
fn test_bloom_filter() {
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
