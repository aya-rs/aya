use aya::{
    include_bytes_aligned,
    maps::{AsyncPerfEventArray, HashMap},
    programs::UProbe,
    util::online_cpus,
    Bpf,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::warn;
use tokio::task;

use crate::STACK_ARGUMENT;

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_stack_argument(
    a_0: u64,
    a_1: u64,
    a_2: u64,
    a_3: u64,
    a_4: u64,
    a_5: u64,
    //in x86_64, from arg6, stack_argument would be used
    a_6: u64,
    a_7: i64,
) {
}

#[tokio::test]
async fn stack_argument() {
    event_logger::init();
    let mut bpf = Bpf::load(crate::STACK_ARGUMENT).unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_stack_argument")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach(Some("trigger_stack_argument"), 0, "/proc/self/exe", None)
        .unwrap();
    let mut args_map = HashMap::try_from(bpf.take_map("ARGS").unwrap())?;
    trigger_stack_argument(0, 1, 2, 3, 4, 5, 6, 7);

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(args_map.keys().count(), 8);
    for iter in args_map.iter() {
        let iter_v = iter.unwrap();
        assert_eq!(iter_v.0, iter_v.1);
    }
}
