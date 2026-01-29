use aya::{
    Ebpf,
    maps::{Array, ArrayOfMaps, HashMap, HashMapOfMaps, MapData},
    programs::UProbe,
};

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_array_of_maps() {
    std::hint::black_box(());
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_hash_of_maps() {
    std::hint::black_box(());
}

/// Test `ArrayOfMaps`: set inner maps and verify eBPF can access them
#[test_log::test]
fn array_of_maps() {
    let mut ebpf = Ebpf::load(crate::MAP_OF_MAPS).unwrap();

    // Clone the inner map FDs to avoid borrow conflicts
    let inner_array_1_fd = ebpf.map("INNER_ARRAY_1").unwrap().fd().try_clone().unwrap();
    let inner_array_2_fd = ebpf.map("INNER_ARRAY_2").unwrap().fd().try_clone().unwrap();

    // Set inner maps into the outer ArrayOfMaps
    {
        let mut outer: ArrayOfMaps<&mut MapData> =
            ebpf.map_mut("ARRAY_OF_MAPS").unwrap().try_into().unwrap();
        outer.set(0, &inner_array_1_fd, 0).unwrap();
        outer.set(1, &inner_array_2_fd, 0).unwrap();
    }

    // Load and attach the uprobe
    {
        let prog: &mut UProbe = ebpf
            .program_mut("test_array_of_maps")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        prog.attach("trigger_array_of_maps", "/proc/self/exe", None)
            .unwrap();
    }

    // Trigger the probe
    trigger_array_of_maps();

    // Verify the eBPF program wrote to the inner maps
    let inner_1: Array<&MapData, u32> = ebpf.map("INNER_ARRAY_1").unwrap().try_into().unwrap();
    let inner_2: Array<&MapData, u32> = ebpf.map("INNER_ARRAY_2").unwrap().try_into().unwrap();

    assert_eq!(inner_1.get(&0, 0).unwrap(), 42);
    assert_eq!(inner_2.get(&0, 0).unwrap(), 24);

    // Verify the results array was updated
    let results: Array<&MapData, u32> = ebpf.map("RESULTS").unwrap().try_into().unwrap();
    assert_eq!(results.get(&0, 0).unwrap(), 1);
}

/// Test `HashOfMaps`: set inner maps and verify eBPF can access them
#[test_log::test]
fn hash_of_maps() {
    let mut ebpf = Ebpf::load(crate::MAP_OF_MAPS).unwrap();

    // Clone the inner map FDs to avoid borrow conflicts
    let inner_hash_1_fd = ebpf.map("INNER_HASH_1").unwrap().fd().try_clone().unwrap();
    let inner_hash_2_fd = ebpf.map("INNER_HASH_2").unwrap().fd().try_clone().unwrap();

    // Set inner maps into the outer HashOfMaps
    {
        let mut outer: HashMapOfMaps<&mut MapData, u32> =
            ebpf.map_mut("HASH_OF_MAPS").unwrap().try_into().unwrap();
        outer.insert(0u32, &inner_hash_1_fd, 0).unwrap();
        outer.insert(1u32, &inner_hash_2_fd, 0).unwrap();
    }

    // Load and attach the uprobe
    {
        let prog: &mut UProbe = ebpf
            .program_mut("test_hash_of_maps")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        prog.attach("trigger_hash_of_maps", "/proc/self/exe", None)
            .unwrap();
    }

    // Trigger the probe
    trigger_hash_of_maps();

    // Verify the eBPF program wrote to the inner maps
    let inner_1: HashMap<&MapData, u32, u32> =
        ebpf.map("INNER_HASH_1").unwrap().try_into().unwrap();
    let inner_2: HashMap<&MapData, u32, u32> =
        ebpf.map("INNER_HASH_2").unwrap().try_into().unwrap();

    assert_eq!(inner_1.get(&100, 0).unwrap(), 42);
    assert_eq!(inner_2.get(&100, 0).unwrap(), 24);

    // Verify the results array was updated
    let results: Array<&MapData, u32> = ebpf.map("RESULTS").unwrap().try_into().unwrap();
    assert_eq!(results.get(&1, 0).unwrap(), 1);
}

/// Test dynamic inner map creation: create inner maps programmatically and use them with `HashOfMaps`
#[test_log::test]
fn hash_of_maps_dynamic() {
    let mut ebpf = Ebpf::load(crate::MAP_OF_MAPS).unwrap();

    // Create inner maps dynamically with the same max_entries as the template (10)
    // Note: max_entries must match the template used when creating the outer map
    let mut inner_1: HashMap<MapData, u32, u32> = HashMap::create(10, 0).unwrap();
    let mut inner_2: HashMap<MapData, u32, u32> = HashMap::create(10, 0).unwrap();

    // Pre-populate the dynamic inner maps with some data
    inner_1.insert(100u32, 1000u32, 0).unwrap();
    inner_2.insert(100u32, 2000u32, 0).unwrap();

    // Insert the dynamically created inner maps into the outer HashOfMaps
    {
        let mut outer: HashMapOfMaps<&mut MapData, u32> =
            ebpf.map_mut("HASH_OF_MAPS").unwrap().try_into().unwrap();
        // Use keys 10 and 11 to avoid conflict with the other test
        outer.insert(10u32, inner_1.fd(), 0).unwrap();
        outer.insert(11u32, inner_2.fd(), 0).unwrap();
    }

    // Verify we can still read from the dynamically created inner maps
    assert_eq!(inner_1.get(&100, 0).unwrap(), 1000);
    assert_eq!(inner_2.get(&100, 0).unwrap(), 2000);

    // Modify the inner maps and verify changes persist
    inner_1.insert(200u32, 3000u32, 0).unwrap();
    assert_eq!(inner_1.get(&200, 0).unwrap(), 3000);
}
