//! A socket local storage map backed by `BPF_MAP_TYPE_SK_STORAGE`.

use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::AsRawFd,
};

use crate::{
    Pod,
    maps::{MapData, MapError, check_kv_size, hash_map},
};

/// A socket local storage map backed by `BPF_MAP_TYPE_SK_STORAGE`.
///
/// This map type stores values that are owned by individual sockets. The map keys are socket file
/// descriptors and the values can be accessed both from eBPF using [`bpf_sk_storage_get`] and from
/// user space through the methods on this type.
///
/// [`bpf_sk_storage_get`]: https://elixir.bootlin.com/linux/v6.12/source/include/uapi/linux/bpf.h#L4064-L4093
#[doc(alias = "BPF_MAP_TYPE_SK_STORAGE")]
#[derive(Debug)]
pub struct SkStorage<T, V: Pod> {
    pub(crate) inner: T,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, V: Pod> SkStorage<T, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<i32, V>(data)?;

        Ok(Self {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the value associated with `socket`.
    pub fn get(&self, socket: &impl AsRawFd, flags: u64) -> Result<V, MapError> {
        hash_map::get(self.inner.borrow(), &socket.as_raw_fd(), flags)
    }
}

impl<T: BorrowMut<MapData>, V: Pod> SkStorage<T, V> {
    /// Creates or updates the value associated with `socket`.
    pub fn insert(
        &mut self,
        socket: &impl AsRawFd,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), MapError> {
        hash_map::insert(
            self.inner.borrow_mut(),
            &socket.as_raw_fd(),
            value.borrow(),
            flags,
        )
    }

    /// Removes the storage associated with `socket`.
    pub fn remove(&mut self, socket: &impl AsRawFd) -> Result<(), MapError> {
        hash_map::remove(self.inner.borrow_mut(), &socket.as_raw_fd())
    }
}
