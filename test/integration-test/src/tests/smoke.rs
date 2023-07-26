use aya::{
    programs::{loaded_programs, Extension, Xdp, XdpFlags},
    util::KernelVersion,
    Bpf, BpfLoader,
};

#[test]
fn xdp() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 18, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, support for BPF_F_XDP_HAS_FRAGS was added in 5.18.0; see https://github.com/torvalds/linux/commit/c2f2cdb");
        return;
    }

    let mut bpf = Bpf::load(crate::PASS).unwrap();
    let dispatcher: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    dispatcher.load().unwrap();
    dispatcher.attach("lo", XdpFlags::default()).unwrap();
}

#[test]
fn extension() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 9, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, XDP uses netlink");
        return;
    }
    let mut bpf = Bpf::load(crate::MAIN).unwrap();
    let pass: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    pass.load().unwrap();
    pass.attach("lo", XdpFlags::default()).unwrap();

    let mut bpf = BpfLoader::new().extension("drop").load(crate::EXT).unwrap();
    let drop_: &mut Extension = bpf.program_mut("drop").unwrap().try_into().unwrap();
    drop_.load(pass.fd().unwrap(), "xdp_pass").unwrap();
}

#[test]
fn list_loaded_programs() {
    // Load a program.
    let mut bpf = Bpf::load(crate::PASS).unwrap();
    let dispatcher: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    dispatcher.load().unwrap();
    dispatcher.attach("lo", XdpFlags::default()).unwrap();

    // Ensure the loaded_programs() api doesn't panic.
    let prog = loaded_programs()
        .map(|p| p.unwrap())
        .find(|p| p.name_as_str().unwrap() == "pass")
        .unwrap();

    // Ensure all relevant helper functions don't panic.
    prog.name();
    prog.name_as_str();
    prog.id();
    prog.tag();
    prog.program_type();
    prog.gpl_compatible();
    prog.map_ids().unwrap();
    prog.btf_id();
    prog.size_translated();
    prog.size_translated();
    prog.memory_locked().unwrap();
    prog.verified_instruction_count();
    prog.loaded_at();
    prog.fd().unwrap();
}
