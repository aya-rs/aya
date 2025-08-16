use aya::{EbpfLoader, maps::Array, programs::UProbe};
use std::ffi::c_int;

const PEEK_INDEX: u32 = 0;
const POP_INDEX: u32 = 1;

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_queue_push(arg: c_int) {
    core::hint::black_box(arg);
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_queue_peek() {
    core::hint::black_box(trigger_queue_peek);
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_queue_pop() {
    core::hint::black_box(trigger_queue_pop);
}

#[test_log::test]
fn queue_basic() {
    let mut bpf = EbpfLoader::new().load(crate::QUEUE_TEST).unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_queue_push")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_queue_push", "/proc/self/exe", None, None)
        .unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_queue_peek")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_queue_peek", "/proc/self/exe", None, None)
        .unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_queue_pop")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_queue_pop", "/proc/self/exe", None, None)
        .unwrap();

    let array_map = bpf.map("RESULT").unwrap();
    let array = Array::<_, c_int>::try_from(array_map).unwrap();

    for i in 0..9 {
        trigger_queue_push(i);

        trigger_queue_peek();
        assert_eq!(array.get(&PEEK_INDEX, 0).unwrap(), i as c_int);

        trigger_queue_pop();
        assert_eq!(array.get(&POP_INDEX, 0).unwrap(), i as c_int);
    }
}
