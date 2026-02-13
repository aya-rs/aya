use core::ptr;

use aya_ebpf_bindings::bindings::{BPF_F_NO_PREALLOC, BPF_SK_STORAGE_GET_F_CREATE, bpf_sock};

use crate::{
    btf_maps::btf_map_def,
    helpers::generated::{bpf_sk_storage_delete, bpf_sk_storage_get},
    programs::sock_addr::SockAddrContext,
};

btf_map_def!(
    /// A BTF-compatible BPF socket storage map.
    ///
    /// Socket storage maps require `BPF_F_NO_PREALLOC` flag and `max_entries: 0`.
    pub struct SkStorage<T>,
    map_type: BPF_MAP_TYPE_SK_STORAGE,
    max_entries: 0,
    // TODO(https://github.com/rust-lang/rust/issues/76560): this should be:
    //
    // { F | BPF_F_NO_PREALLOC as usize }.
    map_flags: BPF_F_NO_PREALLOC as usize,
    key_type: i32,
    value_type: T,
);

impl<T> SkStorage<T> {
    #[inline(always)]
    fn get_ptr(&self, ctx: &SockAddrContext, value: *mut T, flags: u64) -> *mut T {
        let sock_addr = unsafe { &*ctx.sock_addr };
        let sk = unsafe { sock_addr.__bindgen_anon_1.sk };
        unsafe { bpf_sk_storage_get(self.as_ptr(), sk.cast(), value.cast(), flags) }.cast::<T>()
    }

    /// Gets a mutable reference to the value associated with `sk`.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `sk`.
    #[inline(always)]
    pub unsafe fn get_ptr_mut(&self, ctx: &SockAddrContext) -> *mut T {
        self.get_ptr(ctx, ptr::null_mut(), 0)
    }

    /// Gets a mutable reference to the value associated with `sk`.
    ///
    /// If no value is associated with `sk`, `value` will be inserted.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `sk`.
    #[inline(always)]
    pub unsafe fn get_or_insert_ptr_mut(
        &self,
        ctx: &SockAddrContext,
        value: Option<&mut T>,
    ) -> *mut T {
        self.get_ptr(
            ctx,
            value.map_or(ptr::null_mut(), ptr::from_mut),
            BPF_SK_STORAGE_GET_F_CREATE.into(),
        )
    }

    /// Deletes the value associated with `sk`.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `sk`.
    #[inline(always)]
    pub unsafe fn delete(&self, sk: *mut bpf_sock) -> Result<(), i32> {
        let ret = unsafe { bpf_sk_storage_delete(self.as_ptr(), sk.cast()) };
        if ret == 0 { Ok(()) } else { Err(ret as i32) }
    }
}
