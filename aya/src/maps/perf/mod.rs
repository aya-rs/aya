//! Receive events from eBPF programs using the linux `perf` API.
//!
//! See the [`PerfEventArray` documentation](self::PerfEventArray).
#[cfg(feature = "async")]
mod async_perf_event_array;
mod perf_buffer;
mod perf_event_array;

#[cfg(feature = "async")]
pub use async_perf_event_array::*;
pub use perf_buffer::*;
pub use perf_event_array::*;
