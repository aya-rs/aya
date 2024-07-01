use core::{mem::size_of, ptr::null_mut, slice::from_raw_parts};
use std::collections::HashMap;

use assert_matches::assert_matches;
use aya_obj::{generated::bpf_insn, programs::XdpAttachType, Object, ProgramSection};
use test_log::test;

#[test]
fn run_with_rbpf() {
    let object = Object::parse(crate::PASS).unwrap();

    assert_eq!(object.programs.len(), 1);
    assert_matches!(
        object.programs["pass"].section,
        ProgramSection::Xdp {
            frags: true,
            attach_type: XdpAttachType::Interface
        }
    );

    let instructions = &object
        .functions
        .get(&object.programs["pass"].function_key())
        .unwrap()
        .instructions;
    let data = unsafe {
        from_raw_parts(
            instructions.as_ptr() as *const u8,
            instructions.len() * size_of::<bpf_insn>(),
        )
    };
    // Use rbpf interpreter instead of JIT compiler to ensure platform compatibility.
    let vm = rbpf::EbpfVmNoData::new(Some(data)).unwrap();
    const XDP_PASS: u64 = 2;
    assert_eq!(vm.execute_program().unwrap(), XDP_PASS);
}

static mut MULTIMAP_MAPS: [*mut Vec<u64>; 3] = [null_mut(); 3];

#[test]
fn use_map_with_rbpf() {
    let mut object = Object::parse(crate::MULTIMAP_BTF).unwrap();

    assert_eq!(object.programs.len(), 1);
    assert_matches!(
        object.programs["bpf_prog"].section,
        ProgramSection::UProbe { .. }
    );

    // Initialize maps:
    // - fd: Bitwise OR of the map_id with 0xCAFE00 (used to distinguish fds from indices),
    // - Note that rbpf does not convert fds into real pointers,
    //   so we keeps the pointers to our maps in MULTIMAP_MAPS, to be used in helpers.
    let mut maps = HashMap::new();
    let mut map_instances = vec![vec![0u64], vec![0u64], vec![0u64]];
    for (name, map) in object.maps.iter() {
        assert_eq!(map.key_size(), size_of::<u32>() as u32);
        assert_eq!(map.value_size(), size_of::<u64>() as u32);
        assert_eq!(
            map.map_type(),
            aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_ARRAY as u32
        );

        let map_id = match name.as_str() {
            "map_1" => 0,
            "map_2" => 1,
            "map_pin_by_name" => 2,
            n => panic!("Unexpected map: {n}"),
        };

        let fd = map_id as i32 | 0xCAFE00;
        maps.insert(name.to_owned(), (fd, map.clone()));

        unsafe {
            MULTIMAP_MAPS[map_id] = &mut map_instances[map_id] as *mut _;
        }
    }

    let text_sections = object
        .functions
        .iter()
        .map(|((section_index, _), _)| *section_index)
        .collect();
    let disable_maps = HashMap::new();
    object
        .relocate_maps(
            maps.iter()
                .map(|(s, (fd, map))| (s.as_ref() as &str, *fd, map)),
            &text_sections,
            &disable_maps,
        )
        .expect("Relocation failed");
    // Actually there is no local function call involved.
    object.relocate_calls(&text_sections).unwrap();

    // Executes the program
    assert_eq!(object.programs.len(), 1);
    let instructions = &object
        .functions
        .get(&object.programs["bpf_prog"].function_key())
        .unwrap()
        .instructions;
    let data = unsafe {
        from_raw_parts(
            instructions.as_ptr() as *const u8,
            instructions.len() * size_of::<bpf_insn>(),
        )
    };
    let mut vm = rbpf::EbpfVmNoData::new(Some(data)).unwrap();
    vm.register_helper(2, bpf_map_update_elem_multimap)
        .expect("Helper failed");
    assert_eq!(vm.execute_program().unwrap(), 0);

    assert_eq!(map_instances, [[24], [42], [44]]);

    unsafe {
        MULTIMAP_MAPS.iter_mut().for_each(|v| *v = null_mut());
    }
}

#[track_caller]
fn bpf_map_update_elem_multimap(map: u64, key: u64, value: u64, _: u64, _: u64) -> u64 {
    assert_matches!(map, 0xCAFE00 | 0xCAFE01 | 0xCAFE02);
    let key = *unsafe { (key as usize as *const u32).as_ref().unwrap() };
    let value = *unsafe { (value as usize as *const u64).as_ref().unwrap() };
    assert_eq!(key, 0);
    unsafe {
        let map_instance = MULTIMAP_MAPS[map as usize & 0xFF].as_mut().unwrap();
        map_instance[0] = value;
    }
    0
}
