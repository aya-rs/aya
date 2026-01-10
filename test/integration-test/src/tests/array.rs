use aya::{
    EbpfLoader,
    maps::Array,
    programs::{UProbe, uprobe::Single},
};
use integration_common::array::{GET_INDEX, GET_PTR_INDEX, GET_PTR_MUT_INDEX};

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn set(index: u32, value: u32) {
    std::hint::black_box((index, value));
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn get(index: u32) {
    std::hint::black_box(index);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn get_ptr(index: u32) {
    std::hint::black_box(index);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn get_ptr_mut(index: u32) {
    std::hint::black_box(index);
}

#[test_log::test]
fn test_array() {
    let mut ebpf = EbpfLoader::new().load(crate::ARRAY).unwrap();
    for (result_map, array_map, progs_and_symbols) in [
        // BTF map definitions.
        (
            "RESULT",
            "ARRAY",
            [
                ("set", "set"),
                ("get", "get"),
                ("get_ptr", "get_ptr"),
                ("get_ptr_mut", "get_ptr_mut"),
            ],
        ),
        // Legacy map definitions.
        (
            "RESULT_LEGACY",
            "ARRAY_LEGACY",
            [
                ("set_legacy", "set"),
                ("get_legacy", "get"),
                ("get_ptr_legacy", "get_ptr"),
                ("get_ptr_mut_legacy", "get_ptr_mut"),
            ],
        ),
    ] {
        for (prog_name, symbol) in progs_and_symbols {
            let prog: &mut UProbe = ebpf.program_mut(prog_name).unwrap().try_into().unwrap();
            prog.load().unwrap();
            let prog: &mut UProbe<Single> = prog.expect_single().unwrap();
            prog.attach(symbol, "/proc/self/exe", None).unwrap();
        }
        let result_array = ebpf.map(result_map).unwrap();
        let result_array = Array::<_, u32>::try_from(result_array).unwrap();
        let array = ebpf.map(array_map).unwrap();
        let array = Array::<_, u32>::try_from(array).unwrap();
        let seq = 0..9;
        for i in seq.clone() {
            set(i, i.pow(2));
        }
        for i in seq.clone() {
            // Assert the value returned by user-space API.
            let expected_value = i.pow(2);
            let value = array.get(&i, 0).unwrap();
            assert_eq!(value, expected_value);
            // Assert the value returned by eBPF in-kernel API.
            get(i);
            let result = result_array.get(&GET_INDEX, 0).unwrap();
            assert_eq!(result, expected_value);
            get_ptr(i);
            let result = result_array.get(&GET_PTR_INDEX, 0).unwrap();
            assert_eq!(result, expected_value);
        }
        for i in seq.clone() {
            let value = i.pow(2);
            get_ptr_mut(i);
            let result = result_array.get(&GET_PTR_MUT_INDEX, 0).unwrap();
            assert_eq!(result, value);
        }
    }
}
