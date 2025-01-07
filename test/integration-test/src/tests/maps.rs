use aya::{
    maps::{Array, HashMap, MapError},
    programs::UProbe,
    Ebpf,
};

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_hash_map_insert(_key: u32, _value: u32) {
    core::hint::black_box(trigger_hash_map_insert);
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_hash_map_get(_key: u32) {
    core::hint::black_box(trigger_hash_map_get);
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_hash_map_remove(_key: u32) {
    core::hint::black_box(trigger_hash_map_remove);
}

#[test_case::test_case(crate::MAPS; "legacy maps")]
#[test_case::test_case(crate::MAPS_BTF; "BTF maps")]
fn test_hash_map(prog: &[u8]) {
    let mut ebpf = Ebpf::load(prog).unwrap();

    {
        let insert_prog: &mut UProbe = ebpf
            .program_mut("hash_map_insert")
            .unwrap()
            .try_into()
            .unwrap();
        insert_prog.load().unwrap();
        insert_prog
            .attach(Some("trigger_hash_map_insert"), 0, "/proc/self/exe", None)
            .unwrap();

        trigger_hash_map_insert(69, 420);

        let hash_map: HashMap<_, u32, u32> =
            HashMap::try_from(ebpf.map_mut("HASH_MAP").unwrap()).unwrap();
        let value = hash_map.get(&69, 0).unwrap();
        assert_eq!(value, 420);
    }
    {
        let get_prog: &mut UProbe = ebpf
            .program_mut("hash_map_get")
            .unwrap()
            .try_into()
            .unwrap();
        get_prog.load().unwrap();
        get_prog
            .attach(Some("trigger_hash_map_get"), 0, "/proc/self/exe", None)
            .unwrap();

        trigger_hash_map_get(69);

        let results: Array<_, u32> = Array::try_from(ebpf.map_mut("RESULT").unwrap()).unwrap();
        let value = results.get(&0, 0).unwrap();
        assert_eq!(value, 420);
    }
    {
        let remove_prog: &mut UProbe = ebpf
            .program_mut("hash_map_remove")
            .unwrap()
            .try_into()
            .unwrap();
        remove_prog.load().unwrap();
        remove_prog
            .attach(Some("trigger_hash_map_remove"), 0, "/proc/self/exe", None)
            .unwrap();

        trigger_hash_map_remove(69);
        let hash_map: HashMap<_, u32, u32> =
            HashMap::try_from(ebpf.map_mut("HASH_MAP").unwrap()).unwrap();
        let res = hash_map.get(&69, 0);
        assert!(matches!(res.err(), Some(MapError::KeyNotFound)));
    }
}
