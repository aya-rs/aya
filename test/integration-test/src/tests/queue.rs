use aya::{EbpfLoader, maps::Array};

use crate::utils::attach_uprobe;
use integration_common::stack_queue::{PEEK_INDEX, POP_INDEX};

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

    for (probe_name, symbol) in &[
        ("test_queue_push", "trigger_queue_push"),
        ("test_queue_pop", "trigger_queue_pop"),
        ("test_queue_peek", "trigger_queue_peek"),
    ] {
        attach_uprobe(&mut bpf, probe_name, symbol);
    }

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
