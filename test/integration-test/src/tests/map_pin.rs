use std::path::Path;

use assert_matches::assert_matches;
use aya::{
    Ebpf, EbpfError, EbpfLoader,
    maps::{HashMap, IterableMap as _, Map, MapData, MapError, MapType},
    sys::is_map_supported,
};
use rand::RngExt as _;
use scopeguard::defer;

#[test_log::test]
fn loader_reuses_only_compatible_pinned_maps() {
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
    map.insert(&0, &42, 0).unwrap();
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
    assert_eq!(map.get(&0, 0).unwrap(), 42);

    let incompatible_path = pin_path.with_file_name(format!(
        "test_loader_reuse_incompatible_{:x}",
        rand::rng().random::<u64>()
    ));
    let map = HashMap::<MapData, u32, [u8; 4096]>::create(8, 0).unwrap();
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
            actual: 4096,
        } => assert_eq!(name, "BAR"));
    });
    let retained = MapData::from_pin(&incompatible_path)
        .unwrap()
        .info()
        .unwrap();
    assert_eq!(retained.id(), original.id());
    assert_eq!(retained.value_size(), 4096);
}

#[test_log::test]
fn pin_and_reopen_hashmap() {
    let supported = is_map_supported(MapType::Hash).unwrap();
    let mut hash_to_pin = match HashMap::<MapData, u32, u8>::create(8, 0) {
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
    hash_to_pin.insert(&0, &1, 0).unwrap();

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
    assert_eq!(hash_from_pin.get(&0, 0).unwrap(), 1);

    // Try updating data in the map using the pin to verify both maps point and can mutate the same data.
    hash_from_pin.insert(&0, &2, 0).unwrap();
    assert_eq!(hash_to_pin.get(&0, 0).unwrap(), 2);
    assert_eq!(hash_from_pin.get(&0, 0).unwrap(), 2);
}
