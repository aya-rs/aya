use aya::{programs::Lsm, util::KernelVersion, Ebpf};



#[test]
fn test_lsm_cgroup(){
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 0, 0) {
        eprintln!("skipping lsm_cgroup test on kernel {kernel_version:?}");
        return;
    }


    let mut bpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut Lsm = bpf.program_mut("test_cgrouplsm").unwrap().try_into().unwrap();
}