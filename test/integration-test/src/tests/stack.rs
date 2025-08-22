use aya::{EbpfLoader, maps::Array, programs::UProbe};

use crate::utils::attach_uprobe;

const PEEK_INDEX: u32 = 0;
const POP_INDEX: u32 = 1;

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_stack_push(arg: u64) {
    core::hint::black_box(arg);
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_stack_peek(marker: u64) -> u64 {
    core::hint::black_box(trigger_stack_peek);
    marker + 1
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_stack_pop(marker: u64) -> u64 {
    core::hint::black_box(trigger_stack_pop);
    marker + 2
}

#[test_log::test]
fn stack_basic() {
    let mut bpf = EbpfLoader::new().load(crate::STACK_TEST).unwrap();

    for (probe_name, symbol) in &[
        ("test_stack_push", "trigger_stack_push"),
        ("test_stack_peek", "trigger_stack_peek"),
        ("test_stack_pop", "trigger_stack_pop"),
    ] {
        attach_uprobe(bpf, probe_name, symbol);
    }

    let array_map = bpf.map("RESULT").unwrap();
    let array = Array::<_, u64>::try_from(array_map).unwrap();

    for i in 0..9 {
        trigger_stack_push(i);
    }

    for i in (0..9).rev() {
        trigger_stack_peek(i);
        assert_eq!(array.get(&PEEK_INDEX, 0).unwrap(), i);

        trigger_stack_pop(i);
        assert_eq!(array.get(&POP_INDEX, 0).unwrap(), i);
    }
}
