use aya::Bpf;
use aya::maps::{Array, MapRefMut};
use aya::programs::{Xdp, XdpFlags};
use std::{
    convert::TryFrom,
    convert::TryInto,
    env,
    fs,
    thread,
    time::Duration,
};

use bpf::xdp::XdpData;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}

fn try_main() -> Result<(), anyhow::Error> {
    let path = match env::args().nth(1) {
        Some(iface) => iface,
        None => panic!("not path provided"),
    };
    let iface = match env::args().nth(2) {
        Some(iface) => iface,
        None => "eth0".to_string(),
    };

    let data = fs::read(path)?;
    let mut bpf = Bpf::load(
        &data,
        None)?;

    // get the `xdp_stats` program compiled into `xdp`.
    let probe: &mut Xdp = bpf.program_mut("xdp_stats")?.try_into()?;

    // load the program into the kernel
    probe.load()?;

    // attach to the interface
    probe.attach(&iface, XdpFlags::default())?;

    let xdp_stats_map : Array::<MapRefMut, XdpData> = Array::try_from(bpf.map_mut("xdp_stats_map")?)?;

    for _i in 1..10 {
        let data = xdp_stats_map.get(&0, 0)?;
        println!("packets received: {}", data.packet_count);
        thread::sleep(Duration::from_secs(1));
    };
    Ok(())
}