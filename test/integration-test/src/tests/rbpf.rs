use core::{mem::size_of, ptr::null_mut, slice::from_raw_parts};
use std::collections::HashMap;

use aya::include_bytes_aligned;
use aya_obj::{generated::bpf_insn, Object, ProgramSection};

use super::{integration_test, IntegrationTest};

#[integration_test]
fn run_with_rbpf() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/release/pass");
    let object = Object::parse(bytes).unwrap();

    assert_eq!(object.programs.len(), 1);
    assert!(matches!(
        object.programs["pass"].section,
        ProgramSection::Xdp { .. }
    ));
    assert_eq!(object.programs["pass"].section.name(), "pass");

    let instructions = &object.programs["pass"].function.instructions;
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

static mut MULTIMAP_MAPS: [*mut Vec<u64>; 2] = [null_mut(), null_mut()];

#[integration_test]
fn use_map_with_rbpf() {
    let bytes =
        include_bytes_aligned!("../../../../target/bpfel-unknown-none/release/multimap-btf.bpf.o");
    let mut object = Object::parse(bytes).unwrap();

    assert_eq!(object.programs.len(), 1);
    assert!(matches!(
        object.programs["tracepoint"].section,
        ProgramSection::TracePoint { .. }
    ));
    assert_eq!(object.programs["tracepoint"].section.name(), "tracepoint");

    // Initialize maps:
    // - fd: 0xCAFE00 or 0xCAFE01 (the 0xCAFE00 part is used to distinguish fds from indices),
    // - Note that rbpf does not convert fds into real pointers,
    //   so we keeps the pointers to our maps in MULTIMAP_MAPS, to be used in helpers.
    let mut maps = HashMap::new();
    let mut map_instances = vec![vec![0u64], vec![0u64]];
    for (name, map) in object.maps.iter() {
        assert_eq!(map.key_size(), size_of::<u32>() as u32);
        assert_eq!(map.value_size(), size_of::<u64>() as u32);
        assert_eq!(
            map.map_type(),
            aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_ARRAY as u32
        );

        let map_id = if name == "map_1" { 0 } else { 1 };
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
    object
        .relocate_maps(
            maps.iter()
                .map(|(s, (fd, map))| (s.as_ref() as &str, Some(*fd), map)),
            &text_sections,
        )
        .expect("Relocation failed");
    // Actually there is no local function call involved.
    object.relocate_calls(&text_sections).unwrap();

    // Executes the program
    assert_eq!(object.programs.len(), 1);
    let instructions = &object.programs["tracepoint"].function.instructions;
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

    assert_eq!(map_instances[0][0], 24);
    assert_eq!(map_instances[1][0], 42);

    unsafe {
        MULTIMAP_MAPS[0] = null_mut();
        MULTIMAP_MAPS[1] = null_mut();
    }
}

fn bpf_map_update_elem_multimap(map: u64, key: u64, value: u64, _: u64, _: u64) -> u64 {
    assert!(map == 0xCAFE00 || map == 0xCAFE01);
    let key = *unsafe { (key as usize as *const u32).as_ref().unwrap() };
    let value = *unsafe { (value as usize as *const u64).as_ref().unwrap() };
    assert_eq!(key, 0);
    unsafe {
        let map_instance = MULTIMAP_MAPS[map as usize & 0xFF].as_mut().unwrap();
        map_instance[0] = value;
    }
    0
}
