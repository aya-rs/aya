use core::mem::{self, MaybeUninit};

use aya_bpf_bindings::helpers as gen;
pub use gen::*;

use crate::cty::{c_char, c_long, c_void};

#[inline]
pub unsafe fn bpf_probe_read<T>(src: *const T) -> Result<T, c_long> {
    let mut v: MaybeUninit<T> = MaybeUninit::uninit();
    let ret = gen::bpf_probe_read(
        v.as_mut_ptr() as *mut c_void,
        mem::size_of::<T>() as u32,
        src as *const c_void,
    );
    if ret < 0 {
        return Err(ret);
    }

    Ok(v.assume_init())
}

#[inline]
pub unsafe fn bpf_probe_read_user_str(src: *const u8, dest: &mut [u8]) -> Result<usize, c_long> {
    let len = gen::bpf_probe_read_user_str(
        dest.as_mut_ptr() as *mut c_void,
        dest.len() as u32,
        src as *const c_void,
    );
    if len < 0 {
        return Err(-1);
    }

    let mut len = len as usize;
    if len > dest.len() {
        // this can never happen, it's needed to tell the verifier that len is
        // bounded
        len = dest.len();
    }
    Ok(len as usize)
}

#[inline]
pub fn bpf_get_current_comm() -> Result<[c_char; 16], c_long> {
    let mut comm: [c_char; 16usize] = [0; 16];
    let ret = unsafe { gen::bpf_get_current_comm(&mut comm as *mut _ as *mut c_void, 16u32) };
    if ret == 0 {
        Ok(comm)
    } else {
        Err(ret)
    }
}

#[inline]
pub fn bpf_get_current_pid_tgid() -> u64 {
    unsafe { gen::bpf_get_current_pid_tgid() }
}
