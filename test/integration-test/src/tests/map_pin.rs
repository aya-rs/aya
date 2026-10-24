use std::path::Path;

use assert_matches::assert_matches;
use aya::{
    Ebpf, EbpfError, EbpfLoader,
    maps::{HashMap, IterableMap as _, Map, MapData, MapError, MapType},
    sys::is_map_supported,
    util::nr_cpus,
};
use aya_obj::generated::{BPF_F_NO_COMMON_LRU, BPF_F_RDONLY_PROG};
use rand::RngExt as _;
use rstest::rstest;
use scopeguard::defer;

#[test_log::test]
fn loader_reuses_only_compatible_pinned_maps() {
    const KEY: u32 = 0;
    const VALUE: u8 = 42;
    const MAX_ENTRIES: u32 = 8;
    const INCOMPATIBLE_VALUE_SIZE: u32 = 4096;

    let hash_supported = is_map_supported(MapType::Hash).unwrap();
    let array_supported = is_map_supported(MapType::Array).unwrap();
    let mut bpf = match Ebpf::load(crate::MAP_TEST) {
        Ok(bpf) => {
            assert!(hash_supported);
            assert!(array_supported);
            bpf
        }
        Err(error) => {
            assert_matches!(error, EbpfError::MapError(error) => {
                assert_matches!(error, MapError::CreateError { name, io_error } => {
                    match name.as_str() {
                        "BAR" => assert!(!hash_supported),
                        "FOO" => assert!(!array_supported),
                        "MAP_WITH_LOOOONG_NAAAAAAAAME" => assert!(!hash_supported),
                        name => panic!("unexpected map {name}"),
                    }
                    assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL));
                });
            });
            return;
        }
    };

    let pin_path = Path::new("/sys/fs/bpf").join(format!(
        "test_loader_reuse_{:x}",
        rand::rng().random::<u64>()
    ));
    let mut map: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("BAR").unwrap()).unwrap();
    map.insert(&KEY, &VALUE, 0).unwrap();
    map.pin(&pin_path).unwrap();
    defer! { std::fs::remove_file(&pin_path).unwrap() }
    let original = MapData::from_pin(&pin_path).unwrap().info().unwrap();
    let reopened = EbpfLoader::new()
        .map_pin_path("BAR", &pin_path)
        .load(crate::MAP_TEST)
        .unwrap();
    assert_matches!(reopened.map("BAR"), Some(Map::HashMap(data)) => {
        assert_eq!(data.info().unwrap().id(), original.id());
    });
    let map: HashMap<_, u32, u8> = HashMap::try_from(reopened.map("BAR").unwrap()).unwrap();
    assert_eq!(map.get(&KEY, 0).unwrap(), VALUE);

    let incompatible_path = pin_path.with_file_name(format!(
        "test_loader_reuse_incompatible_{:x}",
        rand::rng().random::<u64>()
    ));
    let map =
        HashMap::<MapData, u32, [u8; INCOMPATIBLE_VALUE_SIZE as usize]>::create(MAX_ENTRIES, 0)
            .unwrap();
    map.pin(&incompatible_path).unwrap();
    defer! { std::fs::remove_file(&incompatible_path).unwrap() }
    let original = MapData::from_pin(&incompatible_path)
        .unwrap()
        .info()
        .unwrap();
    let error = EbpfLoader::new()
        .map_pin_path("BAR", &incompatible_path)
        .load(crate::MAP_TEST)
        .unwrap_err();
    assert_matches!(error, EbpfError::MapError(error) => {
        assert_matches!(error, MapError::IncompatiblePinnedMap {
            name,
            property: "value_size",
            expected: 1,
            actual,
        } => {
            assert_eq!(name, "BAR");
            assert_eq!(actual, u64::from(INCOMPATIBLE_VALUE_SIZE));
        });
    });
    let retained = MapData::from_pin(&incompatible_path)
        .unwrap()
        .info()
        .unwrap();
    assert_eq!(retained.id(), original.id());
    assert_eq!(retained.value_size(), INCOMPATIBLE_VALUE_SIZE);
}

#[test_log::test]
fn pin_and_reopen_hashmap() {
    const KEY: u32 = 0;
    const INITIAL_VALUE: u8 = 1;
    const UPDATED_VALUE: u8 = 2;
    const MAX_ENTRIES: u32 = 8;

    let supported = is_map_supported(MapType::Hash).unwrap();
    let mut hash_to_pin = match HashMap::<MapData, u32, u8>::create(MAX_ENTRIES, 0) {
        Ok(map) => {
            assert!(supported);
            map
        }
        Err(error) => {
            assert_matches!(error, MapError::CreateError { name, io_error } => {
                assert_eq!(name, "standalone_hash");
                assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL));
                assert!(!supported);
            });
            return;
        }
    };
    hash_to_pin.insert(&KEY, &INITIAL_VALUE, 0).unwrap();

    let mut rng = rand::rng();
    let pin_path = Path::new("/sys/fs/bpf/").join(format!(
        "test_pin_and_reopen_hashmap_{:x}",
        rng.random::<u64>()
    ));
    hash_to_pin.map().pin(&pin_path).unwrap();
    defer! {
        std::fs::remove_file(&pin_path).unwrap();
    }

    // This is the critical part of the test. We reopen the map using the pin and verify both
    // references point to the same underlying map data.
    let reopened_map_data = MapData::from_pin(&pin_path).unwrap();
    let mut reopened_map = Map::from_map_data(reopened_map_data).unwrap();
    let mut hash_from_pin: HashMap<_, u32, u8> = HashMap::try_from(&mut reopened_map).unwrap();
    assert_eq!(hash_from_pin.get(&KEY, 0).unwrap(), INITIAL_VALUE);

    // Try updating data in the map using the pin to verify both maps point and can mutate the same data.
    hash_from_pin.insert(&KEY, &UPDATED_VALUE, 0).unwrap();
    assert_eq!(hash_to_pin.get(&KEY, 0).unwrap(), UPDATED_VALUE);
    assert_eq!(hash_from_pin.get(&KEY, 0).unwrap(), UPDATED_VALUE);
}

#[rstest]
#[case::devmap("DEVMAP", MapType::DevMap)]
#[case::devmap_hash("DEVMAP_HASH", MapType::DevMapHash)]
#[case::lru_hash("LRU_HASH", MapType::LruHash)]
#[case::lru_percpu("LRU_PERCPU", MapType::LruPerCpuHash)]
#[test_attr(test_log::test)]
fn loader_reuses_kernel_normalized_maps(
    #[case] name: &str,
    #[case] map_type: MapType,
    #[values(false, true)] explicit_path: bool,
) {
    let directory = tempfile::Builder::new()
        .prefix("aya_map_reuse_")
        .tempdir_in("/sys/fs/bpf")
        .unwrap();
    let cpus = u32::try_from(nr_cpus().unwrap()).unwrap();
    // When there is more than one possible CPU, the LRU maps must round this up.
    let requested = cpus + 1;
    let first = EbpfLoader::new()
        .default_map_pin_directory(directory.path())
        .map_max_entries(name, requested)
        .load(crate::MAP_REUSE);
    let first = match first {
        Ok(bpf) => {
            assert!(is_map_supported(map_type).unwrap());
            bpf
        }
        Err(error) => {
            assert_matches!(error, EbpfError::MapError(error) => {
                assert_matches!(error, MapError::CreateError { name, io_error } => {
                    let map_type = match name.as_str() {
                        "DEVMAP" => MapType::DevMap,
                        "DEVMAP_HASH" => MapType::DevMapHash,
                        "LRU_HASH" => MapType::LruHash,
                        "LRU_PERCPU" => MapType::LruPerCpuHash,
                        name => panic!("unexpected map {name}"),
                    };
                    assert!(!is_map_supported(map_type).unwrap());
                    assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL));
                });
            });
            return;
        }
    };
    let pin_path = directory.path().join(name);
    let original = MapData::from_pin(&pin_path).unwrap().info().unwrap();
    assert_eq!(original.map_type().unwrap(), map_type);
    match map_type {
        MapType::LruHash => {
            assert_eq!(original.max_entries(), cpus * 2);
            assert_eq!(original.map_flags(), BPF_F_NO_COMMON_LRU);
        }
        MapType::LruPerCpuHash => {
            assert_eq!(original.max_entries(), cpus * 2);
            assert_eq!(original.map_flags(), BPF_F_NO_COMMON_LRU);
        }
        MapType::DevMap => {
            assert_eq!(original.max_entries(), requested);
            assert_eq!(original.map_flags() & !BPF_F_RDONLY_PROG, 0);
        }
        MapType::DevMapHash => {
            assert_eq!(original.max_entries(), requested);
            assert_eq!(original.map_flags() & !BPF_F_RDONLY_PROG, 0);
        }
        map_type => panic!("unexpected map type {map_type:?}"),
    }
    drop(first);

    let other_directory = tempfile::Builder::new()
        .prefix("aya_map_reuse_other_")
        .tempdir_in("/sys/fs/bpf")
        .unwrap();
    let mut loader = EbpfLoader::new();
    loader
        .default_map_pin_directory(if explicit_path {
            other_directory.path()
        } else {
            directory.path()
        })
        .map_max_entries(name, requested);
    if explicit_path {
        loader.map_pin_path(name, &pin_path);
    }
    let mut reused = loader.load(crate::MAP_REUSE).unwrap();
    let data = match reused.take_map(name).unwrap() {
        Map::DevMap(data) => data,
        Map::DevMapHash(data) => data,
        Map::LruHashMap(data) => data,
        Map::PerCpuLruHashMap(data) => data,
        map => panic!("unexpected map {map:?}"),
    };
    assert_eq!(data.info().unwrap().id(), original.id());

    // A different effective capacity must still fail without replacing the pin.
    loader.map_max_entries(name, original.max_entries() + 1);
    let error = loader.load(crate::MAP_REUSE).unwrap_err();
    assert_matches!(error, EbpfError::MapError(error) => {
        assert_matches!(error, MapError::IncompatiblePinnedMap {
            name: actual_name,
            property: "max_entries",
            expected,
            actual,
        } => {
            assert_eq!(actual_name, name);
            assert!(expected > actual);
            assert_eq!(actual, u64::from(original.max_entries()));
        });
    });
    assert_eq!(
        MapData::from_pin(&pin_path).unwrap().info().unwrap().id(),
        original.id(),
    );
    log::info!(
        "verified {map_type:?} reuse: explicit_path={explicit_path}, requested={requested}, effective={}, flags={:#x}",
        original.max_entries(),
        original.map_flags(),
    );
}
