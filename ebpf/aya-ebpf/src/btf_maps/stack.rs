use core::{borrow::Borrow, mem::MaybeUninit, ptr};

use aya_ebpf_bindings::bindings::BPF_F_NO_PREALLOC;

use crate::{
    btf_maps::btf_map_def,
    helpers::{bpf_map_peek_elem, bpf_map_pop_elem, bpf_map_push_elem},
};

btf_map_def!(
    /// A BTF-compatible BPF stack map.
    ///
    /// Stacks store values of type `T` in LIFO order. Push appends to the
    /// top; pop and peek read from the top. There is no per-element key.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.20.
    /// `BPF_MAP_TYPE_STACK` and `BPF_MAP_TYPE_QUEUE` landed together.
    ///
    /// # Flag and size restrictions
    ///
    /// The kernel rejects stack maps with `BPF_F_NO_PREALLOC` and returns
    /// `EINVAL`. The value must be non-zero sized and `max_entries` must
    /// be at least 1.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::Stack, macros::btf_map};
    ///
    /// #[btf_map]
    /// static FRAMES: Stack<u64, 64> = Stack::new();
    /// ```
    pub struct Stack<T; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_STACK,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: (),
    value_type: T,
);

impl<T, const MAX_ENTRIES: usize, const FLAGS: usize> Stack<T, MAX_ENTRIES, FLAGS> {
    const _CHECK: () = {
        assert!(size_of::<T>() > 0, "stack value must be non-zero sized.");
        assert!(
            MAX_ENTRIES > 0,
            "stack max_entries must be greater than zero.",
        );
        assert!(
            FLAGS & BPF_F_NO_PREALLOC as usize == 0,
            "BPF_F_NO_PREALLOC is rejected by stack maps.",
        );
    };

    /// Pushes `value` onto the top of the stack.
    ///
    /// `flags` is forwarded to `bpf_map_push_elem`; setting `BPF_EXIST`
    /// evicts the bottom element when the stack is full.
    #[inline(always)]
    pub fn push(&self, value: impl Borrow<T>, flags: u64) -> Result<(), i32> {
        let () = Self::_CHECK;
        let ret = unsafe {
            bpf_map_push_elem(self.as_ptr(), ptr::from_ref(value.borrow()).cast(), flags)
        };
        (ret == 0).then_some(()).ok_or(ret as i32)
    }

    /// Removes and returns the top of the stack, or `None` if empty.
    #[inline(always)]
    pub fn pop(&self) -> Option<T> {
        let () = Self::_CHECK;
        unsafe {
            let mut value = MaybeUninit::<T>::uninit();
            let ret = bpf_map_pop_elem(self.as_ptr(), value.as_mut_ptr().cast());
            (ret == 0).then(|| value.assume_init())
        }
    }

    /// Returns the top of the stack without removing it, or `None` if empty.
    #[inline(always)]
    pub fn peek(&self) -> Option<T> {
        let () = Self::_CHECK;
        unsafe {
            let mut value = MaybeUninit::<T>::uninit();
            let ret = bpf_map_peek_elem(self.as_ptr(), value.as_mut_ptr().cast());
            (ret == 0).then(|| value.assume_init())
        }
    }
}
