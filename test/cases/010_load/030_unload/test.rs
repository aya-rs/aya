//! ```cargo
//! [dependencies]
//! aya = { path = "../../../../aya" }
//! ```

use aya::{
    programs::{Xdp, XdpFlags},
    Bpf,
};
use std::convert::TryInto;
use std::process::Command;

fn is_loaded() -> bool {
    let output = Command::new("bpftool").args(&["prog"]).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    stdout.contains("xdp  name ihaveaverylongn  tag")
}

fn assert_loaded(loaded: bool) {
    let state = is_loaded();
    if state == loaded {
        return;
    }
    panic!("Expected loaded: {} but was loaded: {}", loaded, state);
}

fn main() {
    println!("Loading XDP program");
    let mut bpf = Bpf::load_file("test.o").unwrap();
    let dispatcher: &mut Xdp = bpf
        .program_mut("ihaveaverylongname")
        .unwrap()
        .try_into()
        .unwrap();

    dispatcher.load().unwrap();

    let link = dispatcher.attach("eth0", XdpFlags::default()).unwrap();

    dispatcher.unload(false).unwrap();

    assert_loaded(true);

    dispatcher.detach(link).unwrap();

    assert_loaded(false);

    dispatcher.load().unwrap();

    assert_loaded(true);

    dispatcher.attach("eth0", XdpFlags::default()).unwrap();

    assert_loaded(true);

    dispatcher.unload(true).unwrap();

    assert_loaded(false);
}
