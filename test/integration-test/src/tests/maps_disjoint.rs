use aya::{
    Ebpf,
    maps::{Array, HashMap},
    programs::{UProbe, uprobe::Single},
};

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_ebpf_program_maps_disjoint() {
    core::hint::black_box(trigger_ebpf_program_maps_disjoint);
}

#[test_log::test]
fn test_maps_disjoint() {
    let mut bpf: Ebpf = Ebpf::load(crate::MAP_TEST).unwrap();
    let prog: &mut UProbe = bpf
        .program_mut("simple_prog_mut")
        .unwrap()
        .try_into()
        .unwrap();

    prog.load().unwrap();
    let prog: &mut UProbe<Single> = prog.expect_single().unwrap();
    prog.attach("trigger_ebpf_program_maps_disjoint", "/proc/self/exe", None)
        .unwrap();

    let [foo, bar, baz] = bpf.maps_disjoint_mut(["FOO", "BAR", "BAZ"]);

    let mut foo: Array<_, u32> = Array::try_from(foo.unwrap()).unwrap();
    let mut bar: HashMap<_, u32, u8> = HashMap::try_from(bar.unwrap()).unwrap();
    assert!(baz.is_none());

    foo.set(0, 5, 0).unwrap();
    bar.insert(0, 10, 0).unwrap();

    trigger_ebpf_program_maps_disjoint();

    assert_eq!(foo.get(&0, 0).unwrap(), 6);
    assert_eq!(bar.get(&0, 0).unwrap(), 11);
}
