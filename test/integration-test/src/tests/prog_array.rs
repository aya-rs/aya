use aya::{EbpfLoader, maps::ProgramArray, programs::SocketFilter};

/// Test that prog_array entries can be set manually using ProgramArray::set
#[test_log::test]
fn prog_array_manual() {
    let mut ebpf = EbpfLoader::new().load(crate::PROG_ARRAY).unwrap();

    // Load all the programs first
    {
        let main_prog: &mut SocketFilter = ebpf
            .program_mut("prog_array_main")
            .unwrap()
            .try_into()
            .unwrap();
        main_prog.load().unwrap();
    }
    {
        let tail_0: &mut SocketFilter =
            ebpf.program_mut("tail_0").unwrap().try_into().unwrap();
        tail_0.load().unwrap();
    }
    {
        let tail_1: &mut SocketFilter =
            ebpf.program_mut("tail_1").unwrap().try_into().unwrap();
        tail_1.load().unwrap();
    }

    // Get the program FDs (clone them to avoid borrow issues)
    let tail_0_fd = ebpf.program("tail_0").unwrap().fd().unwrap().try_clone().unwrap();
    let tail_1_fd = ebpf.program("tail_1").unwrap().fd().unwrap().try_clone().unwrap();

    // Manually set the program array entries
    let mut jump_table: ProgramArray<_> = ebpf
        .map_mut("JUMP_TABLE")
        .unwrap()
        .try_into()
        .unwrap();
    jump_table.set(0, &tail_0_fd, 0).unwrap();
    jump_table.set(1, &tail_1_fd, 0).unwrap();

    // Verify entries are set by checking indices
    let indices: Vec<u32> = jump_table
        .indices()
        .filter_map(|r| r.ok())
        .collect();
    assert!(indices.contains(&0));
    assert!(indices.contains(&1));
}

/// Test that prog_array entries can be set using EbpfLoader::set_prog_array_entry
/// and Ebpf::populate_prog_arrays
#[test_log::test]
fn prog_array_auto_populate() {
    let mut ebpf = EbpfLoader::new()
        .set_prog_array_entry("JUMP_TABLE", 0, "tail_0")
        .set_prog_array_entry("JUMP_TABLE", 1, "tail_1")
        .load(crate::PROG_ARRAY)
        .unwrap();

    // Load the programs first
    {
        let main_prog: &mut SocketFilter = ebpf
            .program_mut("prog_array_main")
            .unwrap()
            .try_into()
            .unwrap();
        main_prog.load().unwrap();
    }
    {
        let tail_0: &mut SocketFilter =
            ebpf.program_mut("tail_0").unwrap().try_into().unwrap();
        tail_0.load().unwrap();
    }
    {
        let tail_1: &mut SocketFilter =
            ebpf.program_mut("tail_1").unwrap().try_into().unwrap();
        tail_1.load().unwrap();
    }

    // Now populate the program arrays
    ebpf.populate_prog_arrays().unwrap();

    // Verify entries are set
    let jump_table: ProgramArray<_> = ebpf
        .map("JUMP_TABLE")
        .unwrap()
        .try_into()
        .unwrap();
    let indices: Vec<u32> = jump_table
        .indices()
        .filter_map(|r| r.ok())
        .collect();
    assert!(indices.contains(&0));
    assert!(indices.contains(&1));
}

/// Test error handling when populate_prog_arrays is called with unloaded programs
#[test_log::test]
fn prog_array_populate_unloaded_error() {
    let mut ebpf = EbpfLoader::new()
        .set_prog_array_entry("JUMP_TABLE", 0, "tail_0")
        .load(crate::PROG_ARRAY)
        .unwrap();

    // Don't load the programs - populate should fail
    let result = ebpf.populate_prog_arrays();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("has not been loaded yet"),
        "Expected 'has not been loaded yet' error, got: {err}"
    );
}

/// Test error handling when populate_prog_arrays references non-existent program
#[test_log::test]
fn prog_array_populate_missing_program_error() {
    let mut ebpf = EbpfLoader::new()
        .set_prog_array_entry("JUMP_TABLE", 0, "nonexistent_prog")
        .load(crate::PROG_ARRAY)
        .unwrap();

    let result = ebpf.populate_prog_arrays();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("not found"),
        "Expected 'not found' error, got: {err}"
    );
}

/// Test error handling when populate_prog_arrays references non-existent map
#[test_log::test]
fn prog_array_populate_missing_map_error() {
    let mut ebpf = EbpfLoader::new()
        .set_prog_array_entry("NONEXISTENT_MAP", 0, "tail_0")
        .load(crate::PROG_ARRAY)
        .unwrap();

    // Load the program first
    let tail_0: &mut SocketFilter =
        ebpf.program_mut("tail_0").unwrap().try_into().unwrap();
    tail_0.load().unwrap();

    let result = ebpf.populate_prog_arrays();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("not found"),
        "Expected 'not found' error, got: {err}"
    );
}
