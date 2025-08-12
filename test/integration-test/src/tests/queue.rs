use aya::{EbpfLoader, maps::Array, programs::UProbe};

const PEEK_INDEX: u32 = 0;
const POP_INDEX: u32 = 1;

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_queue_push(arg: u64) {
    core::hint::black_box(arg);
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_queue_peek(marker: u64) -> u64 {
    core::hint::black_box(trigger_queue_peek);
    marker + 1
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_queue_pop(marker: u64) -> u64 {
    core::hint::black_box(trigger_queue_pop);
    marker + 2
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
        .program_mut("test_queue_pop")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_queue_pop", "/proc/self/exe", None, None)
        .unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_queue_peek")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_queue_peek", "/proc/self/exe", None, None)
        .unwrap();

    let array_map = bpf.map("RESULT").unwrap();
    let array = Array::<_, u64>::try_from(array_map).unwrap();

    for i in 0..9 {
        trigger_queue_push(i);
    }

    for i in 0..9 {
        trigger_queue_peek(i);
        let peek_value = array.get(&PEEK_INDEX, 0).unwrap();

        trigger_queue_pop(i);
        let pop_value = array.get(&POP_INDEX, 0).unwrap();

        assert_eq!(peek_value, pop_value);
        assert_eq!(pop_value, i);
    }
}
