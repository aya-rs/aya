use std::{
    ffi,
    time::{Duration, Instant},
};

use aya::{maps::MapError, Ebpf};

fn to_map_key(key: &str) -> [ffi::c_char; 32] {
    let mut padded: Vec<_> = key.bytes().map(|b| b as ffi::c_char).collect();
    padded.resize(32, 0);
    padded.try_into().unwrap()
}

#[test]
fn auto_attach_succes() {
    let mut bpf = Ebpf::load(crate::PROBE_AUTO_ATTACH).unwrap();
    bpf.auto_attach();

    let executed_map: aya::maps::HashMap<aya::maps::MapData, [ffi::c_char; 32], u8> =
        aya::maps::HashMap::try_from(bpf.take_map("executed_once").unwrap()).unwrap();

    let fired_probes = ["tp_btf", "tracepoint"];

    let start = Instant::now();
    const TIMEOUT: Duration = Duration::from_secs(1);

    let mut all_fired = false;
    while !all_fired && (Instant::now() - start) < TIMEOUT {
        all_fired = true;
        for probe in fired_probes {
            let executed = match executed_map.get(&to_map_key(probe), 0) {
                Ok(fired) => fired,
                Err(MapError::KeyNotFound) => 0,
                e => e.unwrap(),
            };
            if executed == 0 {
                all_fired = false;
            }
        }
    }
    assert!(all_fired, "Not all expected probes fired");
}
