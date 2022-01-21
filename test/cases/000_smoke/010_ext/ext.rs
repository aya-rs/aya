//! ```cargo
//! [dependencies]
//! aya = { path = "../../../../aya" }
//! ```

use aya::{
    Bpf, BpfLoader,
    programs::{Extension, ProgramFd, Xdp, XdpFlags},
};
use std::convert::TryInto;

fn main() {
    println!("Loading Root XDP program");
    let mut bpf = Bpf::load_file("main.o").unwrap();
    let pass: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    pass.load().unwrap();
    pass.attach("lo", XdpFlags::default()).unwrap();

    println!("Loading Extension Program");
    let mut bpf = BpfLoader::new().extension("drop").load_file("ext.o").unwrap();
    let drop_: &mut Extension = bpf.program_mut("drop").unwrap().try_into().unwrap();
    drop_.load(pass.fd().unwrap(), "xdp_pass").unwrap();
    println!("Success...");
}
