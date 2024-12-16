use core::{cell::UnsafeCell, mem, ptr};

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_QUEUE,
    btf_maps::AyaBtfMapMarker,
    helpers::{bpf_map_pop_elem, bpf_map_push_elem},
};

#[allow(dead_code)]
pub struct QueueDef<T, const M: usize, const F: usize = 0> {
    r#type: *const [i32; BPF_MAP_TYPE_QUEUE as usize],
    value: *const T,
    max_entries: *const [i32; M],
    map_flags: *const [i32; F],

    // Anonymize the struct.
    _anon: AyaBtfMapMarker,
}

#[repr(transparent)]
pub struct Queue<T, const M: usize, const F: usize = 0>(UnsafeCell<QueueDef<T, M, F>>);

unsafe impl<T: Sync, const M: usize, const F: usize> Sync for Queue<T, M, F> {}

impl<T, const M: usize, const F: usize> Queue<T, M, F> {
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(QueueDef {
            r#type: &[0i32; BPF_MAP_TYPE_QUEUE as usize],
            value: ptr::null(),
            max_entries: &[0i32; M],
            map_flags: &[0i32; F],
            _anon: AyaBtfMapMarker::new(),
        }))
    }

    pub fn push(&self, value: &T, flags: u64) -> Result<(), i64> {
        let ret = unsafe {
            bpf_map_push_elem(self.0.get() as *mut _, value as *const _ as *const _, flags)
        };
        (ret == 0).then_some(()).ok_or(ret)
    }

    pub fn pop(&self) -> Option<T> {
        unsafe {
            let mut value = mem::MaybeUninit::uninit();
            let ret = bpf_map_pop_elem(self.0.get() as *mut _, value.as_mut_ptr() as *mut _);
            (ret == 0).then_some(value.assume_init())
        }
    }
}
