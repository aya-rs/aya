use aya::{
    include_bytes_aligned,
    programs::{Extension, Xdp, XdpFlags},
    Ebpf, EbpfLoader,
};
use log::info;

use super::{integration_test, kernel_version, IntegrationTest};

#[integration_test]
fn xdp() -> anyhow::Result<()> {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/pass");
    let mut bpf = Ebpf::load(bytes)?;
    let dispatcher: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    dispatcher.load().unwrap();
    dispatcher.attach("lo", XdpFlags::default()).unwrap();
    Ok(())
}

#[integration_test]
fn extension() -> anyhow::Result<()> {
    let (major, minor, _) = kernel_version()?;
    if major < 5 || minor < 9 {
        info!(
            "skipping as {}.{} does not meet version requirement of 5.9",
            major, minor
        );
        return Ok(());
    }
    // TODO: Check kernel version == 5.9 or later
    let main_bytes =
        include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/main.bpf.o");
    let mut bpf = Ebpf::load(main_bytes)?;
    let pass: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    pass.load().unwrap();
    pass.attach("lo", XdpFlags::default()).unwrap();

    let ext_bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/ext.bpf.o");
    let mut bpf = EbpfLoader::new().extension("drop").load(ext_bytes).unwrap();
    let drop_: &mut Extension = bpf.program_mut("drop").unwrap().try_into().unwrap();
    drop_.load(pass.fd().unwrap(), "xdp_pass").unwrap();
    Ok(())
}
