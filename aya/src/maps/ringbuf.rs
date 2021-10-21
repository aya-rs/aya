//! A [ring buffer map][ringbuf] that may be used to receive events from eBPF programs.
//! As of Linux 5.8, this is the preferred way to transfer per-event data from eBPF
//! programs to userspace.
//!
//! [ringbuf]: https://www.kernel.org/doc/html/latest/bpf/ringbuf.html

use std::{ops::DerefMut, sync::Arc};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_RINGBUF,
    maps::{Map, MapError, MapRefMut},
};

#[doc(alias = "BPF_MAP_TYPE_RINGBUF")]
pub struct RingBuf<T: DerefMut<Target = Map>> {
    _map: Arc<T>,
}

impl<T: DerefMut<Target = Map>> RingBuf<T> {}
