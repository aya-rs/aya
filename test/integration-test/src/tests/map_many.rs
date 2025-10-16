use aya::{
    Ebpf,
    maps::{Array, HashMap},
    programs::UProbe,
};

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_ebpf_program_maps_many() {
    core::hint::black_box(trigger_ebpf_program_maps_many);
}

#[test_log::test]
fn test_maps_many() {
    let mut bpf: Ebpf = Ebpf::load(crate::MAP_TEST).unwrap();
    let prog: &mut UProbe = bpf
        .program_mut("simple_prog_mut")
        .unwrap()
        .try_into()
        .unwrap();

    prog.load().unwrap();
    prog.attach(
        "trigger_ebpf_program_maps_many",
        "/proc/self/exe",
        None,
        None,
    )
    .unwrap();

    let [foo, bar, baz] = bpf.maps_many_mut(["FOO", "BAR", "BAZ"]);
    assert!(foo.is_some());
    assert!(bar.is_some());
    assert!(baz.is_none());

    let mut foo: Array<_, u32> = Array::try_from(foo.unwrap()).unwrap();
    let mut bar: HashMap<_, u32, u8> = HashMap::try_from(bar.unwrap()).unwrap();
    foo.set(0, 5, 0).unwrap();
    bar.insert(0, 10, 0).unwrap();

    trigger_ebpf_program_maps_many();

    assert_eq!(foo.get(&0, 0).unwrap(), 6);
    assert_eq!(bar.get(&0, 0).unwrap(), 11);

    trigger_ebpf_program_maps_many();
    trigger_ebpf_program_maps_many();

    assert_eq!(foo.get(&0, 0).unwrap(), 8);
    assert_eq!(bar.get(&0, 0).unwrap(), 13);
}
