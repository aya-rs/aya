//! A `bpf_spin_lock` in a global variable: the map created for the variable's
//! data section has to carry the BTF that describes the lock.

use std::{
    io, mem,
    os::fd::{AsFd as _, AsRawFd as _},
};

use aya::{
    Ebpf, TestRunOptions,
    maps::{Array, IterableMap as _},
    programs::{TestRun as _, Xdp},
    util::KernelVersion,
};
use libbpf_rs::libbpf_sys::{bpf_map_get_info_by_fd, bpf_map_info};

/// The data section holds the lock, padded to 8 bytes, and the counter.
const PACKETS: usize = 1;

#[test_log::test]
fn global_spin_lock() {
    let mut bpf = Ebpf::load(crate::GLOBAL_SPIN_LOCK).unwrap();

    // Every kernel the tests run on accepts BTF for a data section's map.
    let locked: Array<_, [u64; 2]> = bpf.map(".data.locked").unwrap().try_into().unwrap();
    let mut info: bpf_map_info = unsafe { mem::zeroed() };
    let mut info_len = size_of_val(&info) as u32;
    // SAFETY: Both output pointers refer to writable values, and info_len
    // holds the size of info.
    let result = unsafe {
        bpf_map_get_info_by_fd(
            locked.map().fd().as_fd().as_raw_fd(),
            &raw mut info,
            &raw mut info_len,
        )
    };
    assert_eq!(result, 0, "{}", io::Error::last_os_error());
    assert_ne!(info.btf_id, 0);
    assert_ne!(info.btf_value_type_id, 0);

    // v6.2 (d0d78c1df9b1, "bpf: Allow locking bpf_spin_lock global
    // variables"). Before it, each load of the lock's address got its own
    // register id, so unlocking looked like unlocking a different lock.
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 2, 0) {
        eprintln!(
            "skipping the rest of the test on kernel {kernel_version:?}, locking a global bpf_spin_lock requires 6.2"
        );
        return;
    }

    let prog: &mut Xdp = bpf
        .program_mut("count_packets")
        .unwrap()
        .try_into()
        .unwrap();
    // The verifier refuses the program if the map has no BTF.
    prog.load().unwrap();

    const RUNS: u64 = 3;
    let data_in = [0u8; 64];
    for _ in 0..RUNS {
        let opts = TestRunOptions {
            data_in: Some(&data_in),
            ..TestRunOptions::default()
        };
        prog.test_run(opts).unwrap();
    }

    let locked: Array<_, [u64; 2]> = bpf.map(".data.locked").unwrap().try_into().unwrap();
    assert_eq!(locked.get(&0, 0).unwrap()[PACKETS], RUNS);
}
