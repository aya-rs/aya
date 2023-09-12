use aya::{
    include_bytes_aligned, maps::AsyncPerfEventArray, programs::UProbe, util::online_cpus, Bpf,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::warn;
use tokio::task;

use crate::STACK_ARGUMENT;

pub struct Args {
    a_0: u64,
    a_1: u64,
    a_2: u64,
    a_3: u64,
    a_4: u64,
    a_5: u64,

    a_6: u64,
    a_7: i64,
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_stack_argument(
    a_0: u64,
    a_1: u64,
    a_2: u64,
    a_3: u64,
    a_4: u64,
    a_5: u64,
    //from arg6, stack_argument would be used
    a_6: u64,
    a_7: i64,
) {
}

#[tokio::test]
async fn stack_argument() {
    event_logger::init();
    let mut bpf = Bpf::load(crate::STACK_ARGUMENT).unwrap();

    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let prog: &mut UProbe = bpf
        .program_mut("test_stack_argument")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach(Some("trigger_stack_argument"), 0, "/proc/self/exe", None)
        .unwrap();
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        perf_buffers.push(perf_array.open(cpu_id, None)?);

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const Args;
                    let data = unsafe { ptr.read_unaligned() };
                    assert_eq!(data.a_0, 0);
                    assert_eq!(data.a_1, 1);
                    assert_eq!(data.a_2, 2);
                    assert_eq!(data.a_3, 3);
                    assert_eq!(data.a_4, 4);
                    assert_eq!(data.a_5, 5);
                    assert_eq!(data.a_6, 6);
                    assert_eq!(data.a_7, 7);
                    break;
                }
            }
        });
    }

    trigger_stack_argument(0, 1, 2, 3, 4, 5, 6, 7);
}
