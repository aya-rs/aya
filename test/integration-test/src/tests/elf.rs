use object::{Object, ObjectSymbol};

#[test]
fn test_maps() {
    let obj_file = object::File::parse(crate::MAP_TEST).unwrap();
    if obj_file.section_by_name("maps").is_none() {
        panic!("No 'maps' ELF section");
    }
    let mut found = false;
    for sym in obj_file.symbols() {
        if let Ok(name) = sym.name() {
            if name == "BAR" {
                found = true;
                break;
            }
        }
    }
    if !found {
        panic!("No symbol 'BAR' in ELF file")
    }
}
