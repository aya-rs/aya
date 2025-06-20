use core::{cell::UnsafeCell, mem};

use crate::{
    EbpfContext, bindings::bpf_map_type::BPF_MAP_TYPE_STACK_TRACE, btf_maps::AyaBtfMapMarker,
    helpers::bpf_get_stackid,
};

const PERF_MAX_STACK_DEPTH: usize = 127;

#[allow(dead_code)]
pub struct StackTraceDef<const M: usize, const F: usize = 0> {
    r#type: *const [i32; BPF_MAP_TYPE_STACK_TRACE as usize],
    key_size: *const [i32; mem::size_of::<u32>()],
    value_size: *const [i32; mem::size_of::<u64>() * PERF_MAX_STACK_DEPTH],
    max_entries: *const [i32; M],
    map_flags: *const [i32; F],

    // Anonymize the struct.
    _anon: AyaBtfMapMarker,
}

#[repr(transparent)]
pub struct StackTrace<const M: usize, const F: usize = 0>(UnsafeCell<StackTraceDef<M, F>>);

unsafe impl<const M: usize, const F: usize> Sync for StackTrace<M, F> {}

impl<const M: usize, const F: usize> StackTrace<M, F> {
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(StackTraceDef {
            r#type: &[0i32; BPF_MAP_TYPE_STACK_TRACE as usize],
            key_size: &[0i32; mem::size_of::<u32>()],
            value_size: &[0i32; mem::size_of::<u64>() * PERF_MAX_STACK_DEPTH],
            max_entries: &[0i32; M],
            map_flags: &[0i32; F],
            _anon: AyaBtfMapMarker::new(),
        }))
    }

    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn get_stackid<C: EbpfContext>(&self, ctx: &C, flags: u64) -> Result<i64, i64> {
        let ret = unsafe { bpf_get_stackid(ctx.as_ptr(), self.0.get() as *mut _, flags) };
        if ret < 0 { Err(ret) } else { Ok(ret) }
    }
}
