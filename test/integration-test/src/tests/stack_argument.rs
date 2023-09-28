use aya::{maps::HashMap, programs::UProbe, Bpf};

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_stack_argument(
    _a_0: u64,
    _a_1: u64,
    _a_2: u64,
    _a_3: u64,
    _a_4: u64,
    _a_5: u64,
    // in x86_64 arch, for C language, the first 6 integer or pointer argument
    // would be passed in registers. The excess arguments would be passed on the stack.
    // This conculusion and further reference could be found from:
    // https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI
    // Notice that other languages, like Golang, or in other archs, like aarch64, may
    // have different convention rules.
    _a_6: u64,
    _a_7: i64,
) {
    core::hint::black_box(trigger_stack_argument);
}

#[tokio::test]
async fn stack_argument() {
    let mut bpf = Bpf::load(crate::STACK_ARGUMENT).unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_stack_argument")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach(Some("trigger_stack_argument"), 0, "/proc/self/exe", None)
        .unwrap();
    let args_map: HashMap<_, u32, u64> = HashMap::try_from(bpf.take_map("ARGS").unwrap()).unwrap();
    trigger_stack_argument(0, 1, 2, 3, 4, 5, 6, 7);

    assert_eq!(args_map.keys().count(), 8);
    for iter in args_map.iter() {
        let iter_v = iter.unwrap();
        assert_eq!(iter_v.0 as u64, iter_v.1);
    }
}
