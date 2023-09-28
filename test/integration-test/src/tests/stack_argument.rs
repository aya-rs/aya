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
    // in x86_64 arch, for C language, the first 6 integer or pointer argument
    // would be passed in registers. The excess arguments would be passed on the stack.
    // This conculusion and further reference could be found from:
    // https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI
    // Notice that other languages, like Golang, or in other archs, like aarch64, may
    // have different convention rules.
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
    let mut args_map: HashMap<_, u32, u64> =
        HashMap::try_from(bpf.take_map("ARGS").unwrap()).unwrap();
    trigger_stack_argument(0, 1, 2, 3, 4, 5, 6, 7);

    assert_eq!(args_map.keys().count(), 8);
    for iter in args_map.iter() {
        let iter_v = iter.unwrap();
        assert_eq!(iter_v.0 as u64, iter_v.1);
    }
}
