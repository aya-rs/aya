mod cpu_map;
mod dev_map;
mod dev_map_hash;
mod xsk_map;

use core::cell::UnsafeCell;

use aya_bpf_bindings::{
    bindings::{bpf_map_def, xdp_action::XDP_REDIRECT},
    helpers::bpf_redirect_map,
};
pub use cpu_map::CpuMap;
pub use dev_map::DevMap;
pub use dev_map_hash::DevMapHash;
pub use xsk_map::XskMap;

/// Wrapper aroung the `bpf_redirect_map` function.
///
/// # Return value
///
/// - `Ok(XDP_REDIRECT)` on success.
/// - `Err(_)` of the lowest two bits of `flags` on failure.
#[inline(always)]
fn try_redirect_map(def: &UnsafeCell<bpf_map_def>, key: u32, flags: u64) -> Result<u32, u32> {
    // Return XDP_REDIRECT on success, or the value of the two lower bits of the flags argument on
    // error. Thus I have no idea why it returns a long (i64) instead of something saner, hence the
    // unsigned_abs.
    let ret = unsafe { bpf_redirect_map(def.get() as *mut _, key.into(), flags) };
    match ret.unsigned_abs() as u32 {
        XDP_REDIRECT => Ok(XDP_REDIRECT),
        ret => Err(ret),
    }
}
