use aya::{
    programs::{Extension, Xdp, XdpFlags},
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
    let dispatcher: &mut Xdp = bpf.programs.get_mut("pass").unwrap().try_into().unwrap();
    dispatcher.load(bpf.btf_fd.as_ref()).unwrap();
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
    let pass: &mut Xdp = bpf.programs.get_mut("pass").unwrap().try_into().unwrap();
    pass.load(bpf.btf_fd.as_ref()).unwrap();
    pass.attach("lo", XdpFlags::default()).unwrap();

    let mut bpf = BpfLoader::new().extension("drop").load(crate::EXT).unwrap();
    let drop_: &mut Extension = bpf.programs.get_mut("drop").unwrap().try_into().unwrap();
    drop_
        .load(pass.fd().unwrap(), "xdp_pass", bpf.btf_fd.as_ref())
        .unwrap();
}
