//! Ring buffer types used to receive events from eBPF programs using the linux `perf` API.
//!
//! See the [`PerfEventArray`] and [`AsyncPerfEventArray`].
#[cfg(any(feature = "async", doc))]
mod async_perf_event_array;
mod perf_buffer;
mod perf_event_array;

#[cfg(any(feature = "async", doc))]
pub use async_perf_event_array::*;
pub use perf_buffer::*;
pub use perf_event_array::*;
