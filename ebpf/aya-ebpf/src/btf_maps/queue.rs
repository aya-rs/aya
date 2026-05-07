use core::{borrow::Borrow, mem::MaybeUninit, ptr};

use aya_ebpf_bindings::bindings::BPF_F_NO_PREALLOC;

use crate::{
    btf_maps::btf_map_def,
    helpers::{bpf_map_peek_elem, bpf_map_pop_elem, bpf_map_push_elem},
};

btf_map_def!(
    /// A BTF-compatible BPF queue map.
    ///
    /// Queues store values of type `T` in FIFO order. Push appends to the
    /// tail; pop and peek read from the head. There is no per-element key.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.20.
    /// `BPF_MAP_TYPE_QUEUE` and `BPF_MAP_TYPE_STACK` landed together.
    ///
    /// # Flag and size restrictions
    ///
    /// The kernel rejects queue maps with `BPF_F_NO_PREALLOC` and returns
    /// `EINVAL`. The value must be non-zero sized and `max_entries` must
    /// be at least 1.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::Queue, macros::btf_map};
    ///
    /// #[btf_map]
    /// static EVENTS: Queue<u64, 64> = Queue::new();
    /// ```
    pub struct Queue<T; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_QUEUE,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: (),
    value_type: T,
);

impl<T, const MAX_ENTRIES: usize, const FLAGS: usize> Queue<T, MAX_ENTRIES, FLAGS> {
    const _CHECK: () = {
        assert!(size_of::<T>() > 0, "queue value must be non-zero sized.");
        assert!(
            MAX_ENTRIES > 0,
            "queue max_entries must be greater than zero.",
        );
        assert!(
            FLAGS & BPF_F_NO_PREALLOC as usize == 0,
            "BPF_F_NO_PREALLOC is rejected by queue maps.",
        );
    };

    /// Pushes `value` onto the tail of the queue.
    ///
    /// `flags` is forwarded to `bpf_map_push_elem`; setting `BPF_EXIST`
    /// evicts the oldest element when the queue is full.
    #[inline(always)]
    pub fn push(&self, value: impl Borrow<T>, flags: u64) -> Result<(), i32> {
        let () = Self::_CHECK;
        let ret = unsafe {
            bpf_map_push_elem(self.as_ptr(), ptr::from_ref(value.borrow()).cast(), flags)
        };
        (ret == 0).then_some(()).ok_or(ret as i32)
    }

    /// Removes and returns the head of the queue, or `None` if empty.
    #[inline(always)]
    pub fn pop(&self) -> Option<T> {
        let () = Self::_CHECK;
        unsafe {
            let mut value = MaybeUninit::<T>::uninit();
            let ret = bpf_map_pop_elem(self.as_ptr(), value.as_mut_ptr().cast());
            (ret == 0).then(|| value.assume_init())
        }
    }

    /// Returns the head of the queue without removing it, or `None` if empty.
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
