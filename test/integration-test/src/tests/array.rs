use aya::{EbpfLoader, maps::Array, programs::UProbe};
use integration_common::array::{GET_INDEX, GET_PTR_INDEX, GET_PTR_MUT_INDEX};
use test_case::test_case;

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

#[test_case(
    "RESULT_LEGACY",
    "ARRAY_LEGACY",
    "set_legacy",
    "get_legacy",
    "get_ptr_legacy",
    "get_ptr_mut_legacy"
    ; "legacy"
)]
#[test_case(
    "RESULT",
    "ARRAY",
    "set",
    "get",
    "get_ptr",
    "get_ptr_mut"
    ; "btf"
)]
#[test_log::test]
fn test_array(
    result_map: &str,
    array_map: &str,
    set_prog: &str,
    get_prog: &str,
    get_ptr_prog: &str,
    get_ptr_mut_prog: &str,
) {
    let mut ebpf = EbpfLoader::new().load(crate::ARRAY).unwrap();

    for (prog_name, symbol) in [
        (set_prog, "set"),
        (get_prog, "get"),
        (get_ptr_prog, "get_ptr"),
        (get_ptr_mut_prog, "get_ptr_mut"),
    ] {
        let prog: &mut UProbe = ebpf
            .program_mut(prog_name)
            .unwrap_or_else(|| panic!("missing program {prog_name}"))
            .try_into()
            .unwrap_or_else(|err| panic!("program {prog_name} is not a uprobe: {err}"));
        prog.load()
            .unwrap_or_else(|err| panic!("load {prog_name}: {err}"));
        prog.attach(symbol, "/proc/self/exe", None)
            .unwrap_or_else(|err| panic!("attach {prog_name}: {err}"));
    }

    let result_array = Array::<_, u32>::try_from(ebpf.map(result_map).unwrap()).unwrap();
    let array = Array::<_, u32>::try_from(ebpf.map(array_map).unwrap()).unwrap();

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
    for i in seq {
        let value = i.pow(2);
        get_ptr_mut(i);
        let result = result_array.get(&GET_PTR_MUT_INDEX, 0).unwrap();
        assert_eq!(result, value);
    }
}
