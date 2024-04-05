//! The purpose of this test is to identify if we can prevent a tmpfile from being linked to by
//! storing information in inode storage.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC,
    cty::c_void,
    macros::{lsm, map},
    maps::inode_storage::InodeStorage,
    programs::LsmContext,
};
use aya_log_ebpf::warn;

#[map]
static TMP_INODE_STORE: InodeStorage<usize> = InodeStorage::new(BPF_F_NO_PREALLOC);

#[lsm(hook = "inode_post_create_tmpfile")]
pub fn inode_post_create_tmpfile(ctx: LsmContext) -> i32 {
    unsafe { try_inode_post_create_tmpfile(ctx) }.unwrap_or_else(|ret| ret)
}

unsafe fn try_inode_post_create_tmpfile(ctx: LsmContext) -> Result<i32, i32> {
    let tmpfile: *mut c_void = ctx.arg(1);
    if TMP_INODE_STORE.get_or_insert_ptr(tmpfile, &0).is_none() {
        warn!(&ctx, "Couldn't add information that we deleted a tmp node!");
    }
    Ok(0)
}

#[lsm(hook = "inode_link")]
pub fn inode_link(ctx: LsmContext) -> i32 {
    unsafe { try_inode_link(ctx) }.unwrap_or_else(|ret| ret)
}

unsafe fn try_inode_link(ctx: LsmContext) -> Result<i32, i32> {
    let maybe_tmpfile: *mut c_void = ctx.arg(0);
    if TMP_INODE_STORE.get(maybe_tmpfile).is_some() {
        return Err(130);
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
