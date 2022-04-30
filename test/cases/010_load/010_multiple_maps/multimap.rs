//! ```cargo
//! [dependencies]
//! log = "0.4"
//! simplelog = "0.11"
//! aya = { path = "../../../../aya" }
//! ```

use aya::{
    Bpf,
    programs::{Xdp, XdpFlags},
};
use log::info;
use std::convert::TryInto;

use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};

fn main() {
    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    ).unwrap();
    info!("Loading XDP program");
    let mut bpf = Bpf::load_file("multimap.o").unwrap();
    let pass: &mut Xdp = bpf.program_mut("stats").unwrap().try_into().unwrap();
    pass.load().unwrap();
    pass.attach("eth0", XdpFlags::default()).unwrap();
    info!("Success...");
}
