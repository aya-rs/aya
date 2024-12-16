#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{array::Array, hash_map::HashMap},
    cty::c_long,
    macros::{btf_map, uprobe},
    programs::ProbeContext,
};

#[btf_map]
static HASH_MAP: HashMap<u32, u32, 10> = HashMap::new();

#[btf_map]
static RESULT: Array<u32, 1> = Array::new();

#[uprobe]
pub fn hash_map_insert(ctx: ProbeContext) {
    match try_hash_map_insert(ctx) {
        Ok(_) => {}
        Err(_) => {}
    }
}

fn try_hash_map_insert(ctx: ProbeContext) -> Result<(), c_long> {
    let key: u32 = ctx.arg(0).ok_or(1)?;
    let value: u32 = ctx.arg(1).ok_or(1)?;

    HASH_MAP.insert(&key, &value, 0)?;

    Ok(())
}

#[uprobe]
pub fn hash_map_get(ctx: ProbeContext) {
    match try_hash_map_get(ctx) {
        Ok(_) => {}
        Err(_) => {}
    }
}

fn try_hash_map_get(ctx: ProbeContext) -> Result<(), c_long> {
    // Retrieve the value from the map.
    let key: u32 = ctx.arg(0).ok_or(1)?;
    let res = unsafe { HASH_MAP.get(&key).ok_or(1)? };

    // Save it in the array.
    let ptr = RESULT.get_ptr_mut(0).ok_or(1)?;
    unsafe { *ptr = *res };

    Ok(())
}

#[uprobe]
pub fn hash_map_remove(ctx: ProbeContext) {
    match try_hash_map_remove(ctx) {
        Ok(_) => {}
        Err(_) => {}
    }
}

fn try_hash_map_remove(ctx: ProbeContext) -> Result<(), c_long> {
    let key: u32 = ctx.arg(0).ok_or(1)?;

    HASH_MAP.remove(&key)?;

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
