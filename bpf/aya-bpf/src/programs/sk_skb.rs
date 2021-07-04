use core::{
    ffi::c_void,
    mem::{self, MaybeUninit},
};

use aya_bpf_bindings::helpers::{
    bpf_clone_redirect, bpf_l3_csum_replace, bpf_l4_csum_replace, bpf_skb_adjust_room,
    bpf_skb_change_type, bpf_skb_load_bytes, bpf_skb_store_bytes,
};
use aya_bpf_cty::c_long;

use crate::{bindings::__sk_buff, BpfContext};

pub struct SkSkbContext {
    skb: *mut __sk_buff,
}

impl SkSkbContext {
    pub fn new(skb: *mut __sk_buff) -> SkSkbContext {
        SkSkbContext { skb }
    }

    #[inline]
    pub fn len(&self) -> u32 {
        unsafe { *self.skb }.len
    }

    #[inline]
    pub fn set_mark(&mut self, mark: u32) {
        unsafe { *self.skb }.mark = mark;
    }

    #[inline]
    pub fn cb(&self) -> &[u32] {
        unsafe { &(*self.skb).cb }
    }

    #[inline]
    pub fn cb_mut(&mut self) -> &mut [u32] {
        unsafe { &mut (*self.skb).cb }
    }

    #[inline]
    pub fn load<T>(&self, offset: usize) -> Result<T, c_long> {
        unsafe {
            let mut data = MaybeUninit::<T>::uninit();
            let ret = bpf_skb_load_bytes(
                self.skb as *const _,
                offset as u32,
                &mut data as *mut _ as *mut _,
                mem::size_of::<T>() as u32,
            );
            if ret < 0 {
                return Err(ret);
            }

            Ok(data.assume_init())
        }
    }

    #[inline]
    pub fn store<T>(&mut self, offset: usize, v: &T, flags: u64) -> Result<(), c_long> {
        unsafe {
            let ret = bpf_skb_store_bytes(
                self.skb as *mut _,
                offset as u32,
                v as *const _ as *const _,
                mem::size_of::<T>() as u32,
                flags,
            );
            if ret < 0 {
                return Err(ret);
            }
        }

        Ok(())
    }

    #[inline]
    pub fn l3_csum_replace(
        &self,
        offset: usize,
        from: u64,
        to: u64,
        size: u64,
    ) -> Result<(), c_long> {
        unsafe {
            let ret = bpf_l3_csum_replace(self.skb as *mut _, offset as u32, from, to, size);
            if ret < 0 {
                return Err(ret);
            }
        }

        Ok(())
    }

    #[inline]
    pub fn l4_csum_replace(
        &self,
        offset: usize,
        from: u64,
        to: u64,
        flags: u64,
    ) -> Result<(), c_long> {
        unsafe {
            let ret = bpf_l4_csum_replace(self.skb as *mut _, offset as u32, from, to, flags);
            if ret < 0 {
                return Err(ret);
            }
        }

        Ok(())
    }

    #[inline]
    pub fn adjust_room(&self, len_diff: i32, mode: u32, flags: u64) -> Result<(), c_long> {
        let ret = unsafe { bpf_skb_adjust_room(self.as_ptr() as *mut _, len_diff, mode, flags) };
        if ret < 0 {
            return Err(ret);
        }

        Ok(())
    }

    #[inline]
    pub fn clone_redirect(&self, if_index: u32, flags: u64) -> Result<(), c_long> {
        let ret = unsafe { bpf_clone_redirect(self.as_ptr() as *mut _, if_index, flags) };
        if ret < 0 {
            Err(ret)
        } else {
            Ok(())
        }
    }

    #[inline]
    pub fn change_type(&self, ty: u32) -> Result<(), c_long> {
        let ret = unsafe { bpf_skb_change_type(self.as_ptr() as *mut _, ty) };
        if ret < 0 {
            Err(ret)
        } else {
            Ok(())
        }
    }
}

impl BpfContext for SkSkbContext {
    fn as_ptr(&self) -> *mut c_void {
        self.skb as *mut _
    }
}
