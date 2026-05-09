use aya::{
    EbpfLoader,
    maps::{Array, MapType},
    programs::{UProbe, uprobe::UProbeScope},
    sys::is_map_supported,
};
use integration_common::linear_data_structures::{PEEK_INDEX, POP_INDEX};

enum Order {
    Lifo,
    Fifo,
}

macro_rules! define_linear_ds_host_test {
    (
        push_prog: $push_prog:literal,
        pop_prog: $pop_prog:literal,
        peek_prog: $peek_prog:literal,
        result_map: $result_map:literal,
        push_fn: $push_fn:ident,
        pop_fn: $pop_fn:ident,
        peek_fn: $peek_fn:ident,
        test_fn: $test_fn:ident,
        map_type: $map_type:expr,
        order: $order:expr,
    ) => {
        #[unsafe(no_mangle)]
        #[inline(never)]
        extern "C" fn $push_fn(arg: u64) {
            core::hint::black_box(arg);
        }
        #[unsafe(no_mangle)]
        #[inline(never)]
        extern "C" fn $peek_fn(marker: u64) -> u64 {
            core::hint::black_box($peek_fn);
            marker + 1
        }
        #[unsafe(no_mangle)]
        #[inline(never)]
        extern "C" fn $pop_fn(marker: u64) -> u64 {
            core::hint::black_box($pop_fn);
            marker + 2
        }

        #[test_log::test]
        fn $test_fn() {
            if !is_map_supported($map_type).unwrap() {
                eprintln!("skipping test - {:?} map not supported", $map_type);
                return;
            }
            let mut bpf = EbpfLoader::new()
                .load(crate::LINEAR_DATA_STRUCTURES)
                .unwrap();
            for (prog_name, symbol) in [
                ($push_prog, stringify!($push_fn)),
                ($peek_prog, stringify!($peek_fn)),
                ($pop_prog, stringify!($pop_fn)),
            ] {
                let prog: &mut UProbe = bpf.program_mut(prog_name).unwrap().try_into().unwrap();
                prog.load().unwrap();
                prog.attach(symbol, "/proc/self/exe", UProbeScope::AllProcesses)
                    .unwrap();
            }
            let array = Array::<_, u64>::try_from(bpf.map($result_map).unwrap()).unwrap();
            let seq = 0..9;
            for i in seq.clone() {
                $push_fn(i);
            }
            let mut rev = seq.clone().rev();
            let mut seq = seq;
            let iter: &mut dyn Iterator<Item = u64> = match $order {
                Order::Lifo => &mut rev,
                Order::Fifo => &mut seq,
            };
            for i in iter {
                $peek_fn(i);
                assert_eq!(array.get(&PEEK_INDEX, 0).unwrap(), i);
                $pop_fn(i);
                assert_eq!(array.get(&POP_INDEX, 0).unwrap(), i);
            }
        }
    };
}

define_linear_ds_host_test!(
    push_prog: "test_stack_push_legacy",
    pop_prog: "test_stack_pop_legacy",
    peek_prog: "test_stack_peek_legacy",
    result_map: "RESULT_LEGACY",
    push_fn: trigger_stack_push_legacy,
    pop_fn: trigger_stack_pop_legacy,
    peek_fn: trigger_stack_peek_legacy,
    test_fn: stack_basic_legacy,
    map_type: MapType::Stack,
    order: Order::Lifo,
);

define_linear_ds_host_test!(
    push_prog: "test_stack_push",
    pop_prog: "test_stack_pop",
    peek_prog: "test_stack_peek",
    result_map: "RESULT",
    push_fn: trigger_stack_push,
    pop_fn: trigger_stack_pop,
    peek_fn: trigger_stack_peek,
    test_fn: stack_basic_btf,
    map_type: MapType::Stack,
    order: Order::Lifo,
);

define_linear_ds_host_test!(
    push_prog: "test_queue_push_legacy",
    pop_prog: "test_queue_pop_legacy",
    peek_prog: "test_queue_peek_legacy",
    result_map: "RESULT_LEGACY",
    push_fn: trigger_queue_push_legacy,
    pop_fn: trigger_queue_pop_legacy,
    peek_fn: trigger_queue_peek_legacy,
    test_fn: queue_basic_legacy,
    map_type: MapType::Queue,
    order: Order::Fifo,
);

define_linear_ds_host_test!(
    push_prog: "test_queue_push",
    pop_prog: "test_queue_pop",
    peek_prog: "test_queue_peek",
    result_map: "RESULT",
    push_fn: trigger_queue_push,
    pop_fn: trigger_queue_pop,
    peek_fn: trigger_queue_peek,
    test_fn: queue_basic_btf,
    map_type: MapType::Queue,
    order: Order::Fifo,
);
