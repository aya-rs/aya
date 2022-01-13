//! ```cargo
//! [dependencies]
//! aya = { path = "../../../../aya" }
//! ```

use aya::{
    Bpf,
    programs::{Xdp, XdpFlags},
};
use std::convert::TryInto;
use std::{thread, time};

fn main() {
    println!("Loading XDP program");
    let mut bpf = Bpf::load_file("name_test.o").unwrap();
    let dispatcher: &mut Xdp = bpf.program_mut("ihaveaverylongname").unwrap().try_into().unwrap();
    dispatcher.load().unwrap();
    dispatcher.attach("eth0", XdpFlags::default()).unwrap();
    thread::sleep(time::Duration::from_secs(20));
}
