//! Ring buffer types used to receive events from eBPF programs using the linux
//! `perf` API.
//!
//! See [`PerfEventArray`].
mod perf_buffer;
mod perf_event_array;

pub use perf_buffer::*;
pub use perf_event_array::*;
