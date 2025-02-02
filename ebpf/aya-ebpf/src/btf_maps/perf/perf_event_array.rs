use core::{cell::UnsafeCell, marker::PhantomData, mem};

use crate::{
    bindings::BPF_F_CURRENT_CPU, btf_maps::perf::PerfEventArrayDef, helpers::bpf_perf_event_output,
    EbpfContext,
};

#[repr(transparent)]
pub struct PerfEventArray<T, const F: usize = 0> {
    def: UnsafeCell<PerfEventArrayDef<F>>,
    _t: PhantomData<T>,
}

unsafe impl<T: Sync, const F: usize> Sync for PerfEventArray<T, F> {}

impl<T, const F: usize> PerfEventArray<T, F> {
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            def: UnsafeCell::new(PerfEventArrayDef::new()),
            _t: PhantomData,
        }
    }

    pub fn output<C: EbpfContext>(&self, ctx: &C, data: &T, flags: u32) {
        self.output_at_index(ctx, BPF_F_CURRENT_CPU as u32, data, flags)
    }

    pub fn output_at_index<C: EbpfContext>(&self, ctx: &C, index: u32, data: &T, flags: u32) {
        let flags = (u64::from(flags) << 32) | u64::from(index);
        unsafe {
            bpf_perf_event_output(
                ctx.as_ptr(),
                self.def.get() as *mut _,
                flags,
                data as *const _ as *mut _,
                mem::size_of::<T>() as u64,
            );
        }
    }
}
