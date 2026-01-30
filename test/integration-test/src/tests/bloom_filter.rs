use aya::{
    EbpfLoader,
    maps::{Array, bloom_filter::BloomFilter},
    programs::UProbe,
};
use libc::ENOENT;

const BF_USER_VALUE: u32 = 1;
const BF_KERNEL_VALUE: u32 = 2;

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn test_contains(index: u32) {
    std::hint::black_box(index);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn test_insert(value: u32) {
    std::hint::black_box(value);
}

#[test_log::test]
fn test_bloom_filter_contains_returns_error_item_not_found() {
    let mut ebpf = EbpfLoader::new().load(crate::BLOOM_FILTER).unwrap();
    let contains_prog: &mut UProbe = ebpf
        .program_mut("test_contains")
        .unwrap()
        .try_into()
        .unwrap();
    contains_prog.load().unwrap();
    contains_prog
        .attach("test_contains", "/proc/self/exe", None)
        .unwrap();

    let bloom_filter = {
        let bloom_map = ebpf.map_mut("BLOOMFILTER").unwrap();
        BloomFilter::try_from(bloom_map).unwrap()
    };

    // Test contains from user space
    assert!(bloom_filter.contains(&BF_USER_VALUE, 0).is_err());

    // Test contains from kernel space
    {
        test_contains(BF_KERNEL_VALUE);
        let result = {
            let array_map = ebpf.map("RESULT").unwrap();
            Array::<_, i64>::try_from(array_map).unwrap()
        };
        assert_eq!(result.get(&0, 0).unwrap(), (-ENOENT).into());
    }
}

#[test_log::test]
fn test_bloom_filter_insert_returns_sucessfully() {
    let mut ebpf = EbpfLoader::new().load(crate::BLOOM_FILTER).unwrap();
    let insert_prog: &mut UProbe = ebpf.program_mut("test_insert").unwrap().try_into().unwrap();
    insert_prog.load().unwrap();
    insert_prog
        .attach("test_insert", "/proc/self/exe", None)
        .unwrap();

    let mut bloom_filter = {
        let bloom_map = ebpf.map_mut("BLOOMFILTER").unwrap();
        BloomFilter::try_from(bloom_map).unwrap()
    };

    // Test insert from user space
    assert!(bloom_filter.insert(BF_USER_VALUE, 0).is_ok());

    // Test insert from kernel space
    test_insert(BF_KERNEL_VALUE);
    let result = {
        let array_map = ebpf.map("RESULT").unwrap();
        Array::<_, i64>::try_from(array_map).unwrap()
    };
    assert_eq!(result.get(&0, 0).unwrap(), 1);
}

#[test_log::test]
fn test_bloom_filter_contains_user_space() {
    let mut ebpf = EbpfLoader::new().load(crate::BLOOM_FILTER).unwrap();
    let insert_prog: &mut UProbe = ebpf.program_mut("test_insert").unwrap().try_into().unwrap();
    insert_prog.load().unwrap();
    insert_prog
        .attach("test_insert", "/proc/self/exe", None)
        .unwrap();

    // Test insert from kernel space
    let mut bloom_filter = {
        let bloom_map = ebpf.map_mut("BLOOMFILTER").unwrap();
        BloomFilter::try_from(bloom_map).unwrap()
    };
    assert!(bloom_filter.contains(&BF_KERNEL_VALUE, 0).is_err());
    assert!(bloom_filter.contains(&BF_USER_VALUE, 0).is_err());

    assert!(bloom_filter.insert(BF_USER_VALUE, 0).is_ok());
    test_insert(BF_KERNEL_VALUE);

    assert!(bloom_filter.contains(&BF_KERNEL_VALUE, 0).is_ok());
    assert!(bloom_filter.contains(&BF_USER_VALUE, 0).is_ok());
}

#[test_log::test]
fn test_bloom_filter_contains_kernel_space() {
    let mut ebpf = EbpfLoader::new().load(crate::BLOOM_FILTER).unwrap();
    let contains_prog: &mut UProbe = ebpf
        .program_mut("test_contains")
        .unwrap()
        .try_into()
        .unwrap();
    contains_prog.load().unwrap();
    contains_prog
        .attach("test_contains", "/proc/self/exe", None)
        .unwrap();
    let insert_prog: &mut UProbe = ebpf.program_mut("test_insert").unwrap().try_into().unwrap();
    insert_prog.load().unwrap();
    insert_prog
        .attach("test_insert", "/proc/self/exe", None)
        .unwrap();

    // Test that bloom filter does not contain values before insertion
    for val in [BF_KERNEL_VALUE, BF_USER_VALUE] {
        test_contains(val);
        let result = {
            let array_map = ebpf.map("RESULT").unwrap();
            Array::<_, i64>::try_from(array_map).unwrap()
        };
        assert_eq!(result.get(&0, 0).unwrap(), (-ENOENT).into());
    }

    // Insert elements
    let mut bloom_filter = {
        let bloom_map = ebpf.map_mut("BLOOMFILTER").unwrap();
        BloomFilter::try_from(bloom_map).unwrap()
    };

    // Test that elemts are inserted
    assert!(bloom_filter.insert(BF_USER_VALUE, 0).is_ok());
    test_insert(BF_KERNEL_VALUE);

    for val in [BF_KERNEL_VALUE, BF_USER_VALUE] {
        test_contains(val);
        let result = {
            let array_map = ebpf.map("RESULT").unwrap();
            Array::<_, i64>::try_from(array_map).unwrap()
        };
        assert_eq!(result.get(&0, 0).unwrap(), 1);
    }
}
