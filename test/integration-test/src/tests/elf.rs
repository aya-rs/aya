use object::{Object as _, ObjectSymbol as _};

#[test_log::test]
fn test_maps() {
    let obj_file = object::File::parse(crate::MAP_TEST).unwrap();
    assert!(obj_file.section_by_name("maps").is_some());
    assert!(obj_file.symbols().any(|sym| sym.name() == Ok("BAR")));
}
