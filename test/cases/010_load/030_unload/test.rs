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
    stdout.contains("test_unload")
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
    let dispatcher: &mut Xdp = bpf.program_mut("test_unload").unwrap().try_into().unwrap();

    dispatcher.load().unwrap();

    let link = dispatcher.attach("eth0", XdpFlags::default()).unwrap();

    {
        let link_owned = dispatcher.take_link(link);

        dispatcher.unload().unwrap();

        assert_loaded(true);
    };

    assert_loaded(false);

    dispatcher.load().unwrap();

    assert_loaded(true);

    dispatcher.attach("eth0", XdpFlags::default()).unwrap();

    assert_loaded(true);

    dispatcher.unload().unwrap();

    assert_loaded(false);
}
