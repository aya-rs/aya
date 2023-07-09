use aya::{
    include_bytes_aligned,
    programs::{Extension, Xdp, XdpFlags},
    Bpf, BpfLoader,
};

mod common;
use common::kernel_version;

#[test]
fn xdp() {
    let bytes = include_bytes_aligned!("../../../target/bpfel-unknown-none/release/pass");
    let mut bpf = Bpf::load(bytes).unwrap();
    let dispatcher: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    dispatcher.load().unwrap();
    dispatcher.attach("lo", XdpFlags::default()).unwrap();
}

#[test]
fn extension() {
    let kernel_version = kernel_version().unwrap();
    if kernel_version < (5, 9, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, XDP uses netlink");
        return;
    }
    let main_bytes =
        include_bytes_aligned!("../../../target/bpfel-unknown-none/release/main.bpf.o");
    let mut bpf = Bpf::load(main_bytes).unwrap();
    let pass: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    pass.load().unwrap();
    pass.attach("lo", XdpFlags::default()).unwrap();

    let ext_bytes = include_bytes_aligned!("../../../target/bpfel-unknown-none/release/ext.bpf.o");
    let mut bpf = BpfLoader::new().extension("drop").load(ext_bytes).unwrap();
    let drop_: &mut Extension = bpf.program_mut("drop").unwrap().try_into().unwrap();
    drop_.load(pass.fd().unwrap(), "xdp_pass").unwrap();
}
