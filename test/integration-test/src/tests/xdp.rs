use aya::Bpf;
use object::{Object, ObjectSection, ObjectSymbol, SymbolSection};

#[test]
fn prog_sections() {
    let obj_file = object::File::parse(crate::XDP_SEC).unwrap();

    assert!(has_symbol(&obj_file, "xdp", "xdp_plain"));
    assert!(has_symbol(&obj_file, "xdp.frags", "xdp_frags"));
    assert!(has_symbol(&obj_file, "xdp/cpumap", "xdp_cpumap"));
    assert!(has_symbol(&obj_file, "xdp/devmap", "xdp_devmap"));
    assert!(has_symbol(
        &obj_file,
        "xdp.frags/cpumap",
        "xdp_frags_cpumap"
    ));
    assert!(has_symbol(
        &obj_file,
        "xdp.frags/devmap",
        "xdp_frags_devmap"
    ));
}

fn has_symbol(obj_file: &object::File, sec_name: &str, sym_name: &str) -> bool {
    let sec = obj_file.section_by_name(sec_name).expect(sec_name);
    let sec = SymbolSection::Section(sec.index());
    obj_file
        .symbols()
        .any(|sym| sym.section() == sec && sym.name() == Ok(sym_name))
}

#[test]
fn map_load() {
    let bpf = Bpf::load(crate::XDP_SEC).unwrap();

    bpf.program("xdp_plain").unwrap();
    bpf.program("xdp_frags").unwrap();
    bpf.program("xdp_cpumap").unwrap();
    bpf.program("xdp_devmap").unwrap();
    bpf.program("xdp_frags_cpumap").unwrap();
    bpf.program("xdp_frags_devmap").unwrap();
}
