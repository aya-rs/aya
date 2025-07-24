use std::path::Path;

use aya::{
    Ebpf,
    maps::{HashMap, Map, MapData, MapType},
    programs::{ProgramType, SocketFilter},
    sys::{is_map_supported, is_program_supported},
};
use rand::Rng as _;
use scopeguard::defer;

#[test_log::test]
fn pin_and_reopen_hashmap() {
    // This ProgramType and these two MapTypes are needed because the MAP_TEST sample program uses all three.
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

    // Load the eBPF program to create the file descriptor associated with the BAR map. This is
    // required to read and write to the map which we test below.
    let mut bpf: Ebpf = Ebpf::load(crate::MAP_TEST).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let mut hash_to_pin: HashMap<_, u32, u8> =
        HashMap::try_from(bpf.map_mut("BAR").unwrap()).unwrap();
    hash_to_pin.insert(0, 1, 0).unwrap();

    let mut rng = rand::rng();
    let pin_path = Path::new("/sys/fs/bpf/").join(format!(
        "test_pin_and_reopen_hashmap_{:x}",
        rng.random::<u64>()
    ));
    hash_to_pin.pin(&pin_path).unwrap();
    defer! {
        std::fs::remove_file(&pin_path).unwrap();
    }

    // Get fresh reference since pin() will consume hash_to_pin.
    let hash_from_bpf: HashMap<_, u32, u8> = HashMap::try_from(bpf.map("BAR").unwrap()).unwrap();

    // This is the critical part of the test. We reopen the map using the pin and verify both
    // references point to the same underlying map data without needing to call bpf.map_mut.
    let reopened_map_data = MapData::from_pin(&pin_path).unwrap();
    let mut reopened_map = Map::from_map_data(reopened_map_data).unwrap();
    let mut hash_from_pin: HashMap<_, u32, u8> = HashMap::try_from(&mut reopened_map).unwrap();
    assert_eq!(hash_from_pin.get(&0, 0).unwrap(), 1);

    // Try updating data in the map using the pin to verify both maps point and can mutate the same data.
    hash_from_pin.insert(0, 2, 0).unwrap();
    assert_eq!(hash_from_bpf.get(&0, 0).unwrap(), 2);
    assert_eq!(hash_from_pin.get(&0, 0).unwrap(), 2);
}
