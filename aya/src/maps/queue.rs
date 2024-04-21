//! A FIFO queue.
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::AsFd as _,
};

use crate::{
    maps::{check_kv_size, MapData, MapError},
    sys::{bpf_map_lookup_and_delete_elem, bpf_map_push_elem, SyscallError},
    Pod,
};

/// A FIFO queue.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.20.
///
/// # Examples
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::Queue;
///
/// let mut queue = Queue::try_from(bpf.map_mut("ARRAY").unwrap())?;
/// queue.push(42, 0)?;
/// queue.push(43, 0)?;
/// assert_eq!(queue.pop(0)?, 42);
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_QUEUE")]
pub struct Queue<T, V: Pod> {
    pub(crate) inner: T,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, V: Pod> Queue<T, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<(), V>(data)?;

        Ok(Self {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the number of elements the queue can hold.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn capacity(&self) -> u32 {
        self.inner.borrow().def.max_entries()
    }
}

impl<T: BorrowMut<MapData>, V: Pod> Queue<T, V> {
    /// Removes the first element and returns it.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::ElementNotFound`] if the queue is empty, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_and_delete_elem` fails.
    pub fn pop(&mut self, flags: u64) -> Result<V, MapError> {
        let fd = self.inner.borrow().fd().as_fd();

        let value = bpf_map_lookup_and_delete_elem::<u32, _>(fd, None, flags).map_err(
            |(_, io_error)| SyscallError {
                call: "bpf_map_lookup_and_delete_elem",
                io_error,
            },
        )?;
        value.ok_or(MapError::ElementNotFound)
    }

    /// Appends an element at the end of the queue.
    ///
    /// # Errors
    ///
    /// [`MapError::SyscallError`] if `bpf_map_update_elem` fails.
    pub fn push(&mut self, value: impl Borrow<V>, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.borrow().fd().as_fd();
        bpf_map_push_elem(fd, value.borrow(), flags).map_err(|(_, io_error)| SyscallError {
            call: "bpf_map_push_elem",
            io_error,
        })?;
        Ok(())
    }
}
