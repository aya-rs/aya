use aya::{
    maps::HashMap,
    maps::perf::AsyncPerfEventArray,
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
};
use structopt::StructOpt;
use bytes::BytesMut;
use std::{
    convert::{TryFrom, TryInto}, 
    net::{self, Ipv4Addr},
};
use tokio::{signal, task};

use myapp_common::PacketLog;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    path: String,
    #[structopt(short, long, default_value = "eth0")]
    iface: String,
}

// ANCHOR: main
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();
    let mut bpf = Bpf::load_file(&opt.path)?;
    let program: &mut Xdp = bpf.program_mut("myapp")?.try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())?;

    // ANCHOR: block_address
    let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST")?)?;
    let block_addr : u32 = Ipv4Addr::new(192, 168, 0, 10).try_into()?;
    blocklist.insert(block_addr, 0, 0)?;
    // ANCHOR_END: block_address

    // ANCHOR: map
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    // ANCHOR_END: map

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let src_addr = net::Ipv4Addr::from(data.ipv4_address);
                    println!("LOG: SRC {}, ACTION {}", src_addr, data.action);
                }
            }
        });
    }
    signal::ctrl_c().await.expect("failed to listen for event");
    Ok::<_, anyhow::Error>(())
}
// ANCHOR_END: main
