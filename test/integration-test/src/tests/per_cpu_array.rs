use aya::{
    EbpfLoader,
    maps::{Array, MapType, PerCpuArray, PerCpuValues},
    programs::UProbe,
    sys::is_map_supported,
    util::nr_cpus,
};
use integration_common::array::{GET_INDEX, GET_PTR_INDEX, GET_PTR_MUT_INDEX};
use test_case::test_case;

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_get(index: u32) {
    std::hint::black_box(index);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_get_ptr(index: u32) {
    std::hint::black_box(index);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_get_ptr_mut(index: u32) {
    std::hint::black_box(index);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_set(index: u32, value: u32) {
    std::hint::black_box((index, value));
}

#[test_case(
    "RESULT_LEGACY",
    "ARRAY_LEGACY",
    "get_legacy",
    "get_ptr_legacy",
    "get_ptr_mut_legacy",
    None
    ; "legacy"
)]
#[test_case(
    "RESULT",
    "ARRAY",
    "get",
    "get_ptr",
    "get_ptr_mut",
    Some("set")
    ; "btf"
)]
#[test_log::test]
fn per_cpu_array_basic(
    result_map: &str,
    array_map: &str,
    get_prog: &str,
    get_ptr_prog: &str,
    get_ptr_mut_prog: &str,
    set_prog: Option<&str>,
) {
    if !is_map_supported(MapType::PerCpuArray).unwrap() {
        eprintln!("skipping test - per-cpu array map not supported");
        return;
    }

    let mut bpf = EbpfLoader::new()
        .load(crate::PER_CPU_ARRAY)
        .expect("load per_cpu_array program");

    let probes: &[(&str, &str)] = &[
        (get_prog, "trigger_get"),
        (get_ptr_prog, "trigger_get_ptr"),
        (get_ptr_mut_prog, "trigger_get_ptr_mut"),
    ];
    for (prog_name, symbol) in probes
        .iter()
        .copied()
        .chain(set_prog.map(|name| (name, "trigger_set")))
    {
        let prog: &mut UProbe = bpf
            .program_mut(prog_name)
            .unwrap_or_else(|| panic!("missing program {prog_name}"))
            .try_into()
            .unwrap_or_else(|err| panic!("program {prog_name} is not a uprobe: {err}"));
        prog.load()
            .unwrap_or_else(|err| panic!("load {prog_name}: {err}"));
        prog.attach(symbol, "/proc/self/exe", None)
            .unwrap_or_else(|err| panic!("attach {prog_name}: {err}"));
    }

    let mut array: PerCpuArray<_, u32> = bpf.take_map(array_map).unwrap().try_into().unwrap();
    let result = Array::<_, u32>::try_from(bpf.map(result_map).unwrap()).unwrap();

    const INDEX: u32 = 3;
    const VALUE: u32 = 0xCAFE;

    // Write a uniform value across every CPU slot so the uprobe (which runs
    // on an arbitrary CPU) observes a deterministic value.
    let cpu_count = nr_cpus().unwrap();
    let initial = PerCpuValues::try_from(vec![VALUE; cpu_count]).unwrap();
    array.set(INDEX, initial, 0).unwrap();

    trigger_get(INDEX);
    assert_eq!(result.get(&GET_INDEX, 0).unwrap(), VALUE);

    trigger_get_ptr(INDEX);
    assert_eq!(result.get(&GET_PTR_INDEX, 0).unwrap(), VALUE);

    trigger_get_ptr_mut(INDEX);
    assert_eq!(result.get(&GET_PTR_MUT_INDEX, 0).unwrap(), VALUE);

    if set_prog.is_some() {
        const NEW_VALUE: u32 = 0x1234;
        trigger_set(INDEX, NEW_VALUE);

        // The probe mutates only the executing CPU's slot; every other slot
        // must still hold the uniform value written from user space.
        let after = array.get(&INDEX, 0).unwrap();
        let mut new_count = 0usize;
        for slot in after.iter() {
            match *slot {
                NEW_VALUE => new_count += 1,
                VALUE => {}
                other => panic!("unexpected per-CPU slot value: {other:#x}"),
            }
        }
        assert_eq!(new_count, 1, "set() should mutate exactly one per-CPU slot");
    }
}
