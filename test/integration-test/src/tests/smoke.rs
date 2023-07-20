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
    let Bpf {
        programs, btf_fd, ..
    } = &mut bpf;
    let dispatcher: &mut Xdp = programs.get_mut("pass").unwrap().try_into().unwrap();
    dispatcher.load(btf_fd.as_ref()).unwrap();
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
    let Bpf {
        programs, btf_fd, ..
    } = &mut bpf;
    let pass: &mut Xdp = programs.get_mut("pass").unwrap().try_into().unwrap();
    pass.load(btf_fd.as_ref()).unwrap();
    pass.attach("lo", XdpFlags::default()).unwrap();

    let mut bpf = BpfLoader::new().extension("drop").load(crate::EXT).unwrap();
    let Bpf {
        programs, btf_fd, ..
    } = &mut bpf;

    let drop_: &mut Extension = programs.get_mut("drop").unwrap().try_into().unwrap();
    drop_
        .load(pass.fd().unwrap(), "xdp_pass", btf_fd.as_ref())
        .unwrap();
}
