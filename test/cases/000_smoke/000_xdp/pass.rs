//! ```cargo
//! [dependencies]
//! aya = { path = "../../../../aya" }
//! ```

use aya::{
    Bpf,
    programs::{Xdp, XdpFlags},
};
use std::convert::TryInto;

fn main() {
    println!("Loading XDP program");
    let mut bpf = Bpf::load_file("pass.o").unwrap();
    let dispatcher: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    dispatcher.load().unwrap();
    dispatcher.attach("eth0", XdpFlags::default()).unwrap();
    println!("Success...");
}
