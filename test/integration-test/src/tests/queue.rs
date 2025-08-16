use aya::{EbpfLoader, maps::Array, programs::UProbe};

const PEEK_INDEX: u32 = 0;
const POP_INDEX: u32 = 1;

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_push(arg: i64) {
    core::hint::black_box(arg);
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_peek() {
    core::hint::black_box(trigger_peek);
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_pop() {
    core::hint::black_box(trigger_pop);
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
    prog.attach("trigger_push", "/proc/self/exe", None, None)
        .unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_queue_peek")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_peek", "/proc/self/exe", None, None)
        .unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_queue_pop")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_pop", "/proc/self/exe", None, None)
        .unwrap();

    //let queue = Queue::<_, u64>::try_from(bpf.take_map("TEST_QUEUE").unwrap()).unwrap();
    let array = Array::<_, i64>::try_from(bpf.map("RESULT").unwrap()).unwrap();

    for i in 0..5 {
        trigger_push(i);
        trigger_peek();
        trigger_pop();

        assert_eq!(array.get(&PEEK_INDEX, 0).unwrap(), i);
        assert_eq!(array.get(&POP_INDEX, 0).unwrap(), i);
    }
}
