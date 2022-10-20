//! A FIFO queue.
use std::{
    convert::{AsMut, AsRef},
    marker::PhantomData,
};

use crate::{
    maps::{check_kv_size, MapData, MapError},
    sys::{bpf_map_lookup_and_delete_elem, bpf_map_push_elem},
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
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::maps::Queue;
///
/// let mut queue = Queue::try_from(bpf.map_mut("ARRAY").unwrap())?;
/// queue.push(42, 0)?;
/// queue.push(43, 0)?;
/// assert_eq!(queue.pop(0)?, 42);
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_QUEUE")]
pub struct Queue<T, V: Pod> {
    inner: T,
    _v: PhantomData<V>,
}

impl<T: AsRef<MapData>, V: Pod> Queue<T, V> {
    pub(crate) fn new(map: T) -> Result<Queue<T, V>, MapError> {
        let data = map.as_ref();
        check_kv_size::<(), V>(data)?;

        let _fd = data.fd_or_err()?;

        Ok(Queue {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the number of elements the queue can hold.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn capacity(&self) -> u32 {
        self.inner.as_ref().obj.max_entries()
    }
}

impl<T: AsMut<MapData>, V: Pod> Queue<T, V> {
    /// Removes the first element and returns it.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::ElementNotFound`] if the queue is empty, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_and_delete_elem` fails.
    pub fn pop(&mut self, flags: u64) -> Result<V, MapError> {
        let fd = self.inner.as_mut().fd_or_err()?;

        let value = bpf_map_lookup_and_delete_elem::<u32, _>(fd, None, flags).map_err(
            |(_, io_error)| MapError::SyscallError {
                call: "bpf_map_lookup_and_delete_elem".to_owned(),
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
    pub fn push(&mut self, value: V, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.as_mut().fd_or_err()?;
        bpf_map_push_elem(fd, &value, flags).map_err(|(_, io_error)| MapError::SyscallError {
            call: "bpf_map_push_elem".to_owned(),
            io_error,
        })?;
        Ok(())
    }
}
