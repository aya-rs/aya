use aya::{EbpfLoader, maps::Array, programs::UProbe};

const PEEK_INDEX: u32 = 0;
const POP_INDEX: u32 = 1;

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_stack_push(arg: u64) {
    core::hint::black_box(arg);
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_stack_peek() {
    core::hint::black_box(trigger_stack_peek);
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_stack_pop() {
    core::hint::black_box(trigger_stack_pop);
}

#[test_log::test]
fn stack_basic() {
    let mut bpf = EbpfLoader::new().load(crate::stack_TEST).unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_stack_push")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_stack_push", "/proc/self/exe", None, None)
        .unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_stack_pop")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_stack_pop", "/proc/self/exe", None, None)
        .unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_stack_peek")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_stack_peek", "/proc/self/exe", None, None)
        .unwrap();

    let array_map = bpf.map("RESULT").unwrap();
    let array = Array::<_, u64>::try_from(array_map).unwrap();

    for i in 0..9 {
        trigger_stack_push(i);

        trigger_stack_peek();
        assert_eq!(array.get(&PEEK_INDEX, 0).unwrap(), i);

        trigger_stack_pop();
        assert_eq!(array.get(&POP_INDEX, 0).unwrap(), i);
    }
}
