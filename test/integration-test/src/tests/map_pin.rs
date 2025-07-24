use std::path::PathBuf;

use aya::{
    Ebpf,
    maps::{HashMap, Map, MapData, MapType},
    programs::{ProgramType, SocketFilter},
    sys::{is_map_supported, is_program_supported},
};

#[test_log::test]
fn pin_and_reopen_hashmap() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    } else if !is_map_supported(MapType::Hash).unwrap() {
        eprintln!("skipping test - hash map not supported");
        return;
    } else if !is_map_supported(MapType::Array).unwrap() {
        eprintln!("skipping test - array map not supported");
        return;
    }

    // Load a program with maps
    let mut bpf: Ebpf = Ebpf::load(crate::MAP_TEST).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();

    // Grab the HashMap from the program and insert some data into it
    let mut hash_to_pin: HashMap<_, u32, u8> =
        HashMap::try_from(bpf.map_mut("BAR").unwrap()).unwrap();
    hash_to_pin.insert(0, 1, 0).unwrap();

    // Pin the map
    let pin_path = PathBuf::from("/sys/fs/bpf/pin_and_reopen_hashmap_test");
    let _ = std::fs::remove_file(&pin_path);
    hash_to_pin.pin(&pin_path).unwrap();

    // Get a fresh reference to the original map
    let hash_from_bpf: HashMap<_, u32, u8> = HashMap::try_from(bpf.map("BAR").unwrap()).unwrap();

    // Open the pinned map again
    let reopened_map_data = MapData::from_pin(&pin_path).unwrap();
    let mut reopened_map = Map::from_map_data(reopened_map_data).unwrap();
    let mut hash_from_pin: HashMap<_, u32, u8> = HashMap::try_from(&mut reopened_map).unwrap();

    // Verify that the data is still there
    assert_eq!(hash_from_pin.get(&0, 0).unwrap(), 1);

    // Try updating data in the map using the new pin
    hash_from_pin.insert(0, 2, 0).unwrap();

    // Verify that both maps have the same data
    assert_eq!(hash_from_bpf.get(&0, 0).unwrap(), 2);
    assert_eq!(hash_from_pin.get(&0, 0).unwrap(), 2);
}
