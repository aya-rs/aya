use aya::Bpf;
use object::{Object, ObjectSection, ObjectSymbol, SymbolSection};

#[test]
fn prog_sections() {
    let obj_file = object::File::parse(crate::XDP_SEC).unwrap();

    ensure_symbol(&obj_file, "xdp", "xdp_plain");
    ensure_symbol(&obj_file, "xdp.frags", "xdp_frags");
    ensure_symbol(&obj_file, "xdp/cpumap", "xdp_cpumap");
    ensure_symbol(&obj_file, "xdp/devmap", "xdp_devmap");
    ensure_symbol(&obj_file, "xdp.frags/cpumap", "xdp_frags_cpumap");
    ensure_symbol(&obj_file, "xdp.frags/devmap", "xdp_frags_devmap");
}

#[track_caller]
fn ensure_symbol(obj_file: &object::File, sec_name: &str, sym_name: &str) {
    let sec = obj_file.section_by_name(sec_name).unwrap_or_else(|| {
        let secs = obj_file
            .sections()
            .flat_map(|sec| sec.name().ok().map(|name| name.to_owned()))
            .collect::<Vec<_>>();
        panic!("section {sec_name} not found. available sections: {secs:?}");
    });
    let sec = SymbolSection::Section(sec.index());

    let syms = obj_file
        .symbols()
        .filter(|sym| sym.section() == sec)
        .filter_map(|sym| sym.name().ok())
        .collect::<Vec<_>>();
    assert!(
        syms.contains(&sym_name),
        "symbol not found. available symbols in section: {syms:?}"
    );
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
