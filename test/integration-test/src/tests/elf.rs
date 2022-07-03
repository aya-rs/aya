use super::{integration_test, IntegrationTest};

use anyhow::bail;
use aya::include_bytes_aligned;
use object::{Object, ObjectSymbol};

#[integration_test]
fn test_maps() -> anyhow::Result<()> {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/map_test");
    let obj_file = object::File::parse(bytes)?;
    if obj_file.section_by_name("maps").is_none() {
        bail!("No 'maps' ELF section");
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
        bail!("No symbol 'BAR' in ELF file")
    }
    Ok(())
}
