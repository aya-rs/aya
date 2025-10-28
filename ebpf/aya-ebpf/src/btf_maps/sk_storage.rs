use core::{cell::UnsafeCell, ptr};

use aya_ebpf_bindings::bindings::{
    BPF_F_NO_PREALLOC, BPF_SK_STORAGE_GET_F_CREATE, bpf_map_type::BPF_MAP_TYPE_SK_STORAGE, bpf_sock,
};
use aya_ebpf_cty::{c_long, c_void};

use crate::{
    btf_map_def,
    helpers::generated::{bpf_sk_storage_delete, bpf_sk_storage_get},
    programs::sock_addr::SockAddrContext,
};

btf_map_def!(SkStorageDef, BPF_MAP_TYPE_SK_STORAGE);

// TODO(https://github.com/rust-lang/rust/issues/76560): this should be:
//
// { F | BPF_F_NO_PREALLOC as usize }.
#[repr(transparent)]
pub struct SkStorage<T>(UnsafeCell<SkStorageDef<i32, T, 0, { BPF_F_NO_PREALLOC as usize }>>);

unsafe impl<T: Sync> Sync for SkStorage<T> {}

impl<T> SkStorage<T> {
    #[expect(
        clippy::new_without_default,
        reason = "BPF maps are always used as static variables, therefore this method has to be `const`. `Default::default` is not `const`."
    )]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(SkStorageDef::new()))
    }

    #[inline(always)]
    fn as_ptr(&self) -> *mut c_void {
        let Self(inner) = self;

        inner.get().cast()
    }

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
    /// If no value is associated with `sk`, `value` will be inserted.`
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
    pub unsafe fn delete(&self, sk: *mut bpf_sock) -> Result<(), c_long> {
        let ret = unsafe { bpf_sk_storage_delete(self.as_ptr(), sk.cast()) };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }
}
