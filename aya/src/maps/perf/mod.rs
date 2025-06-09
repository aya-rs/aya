//! Ring buffer types used to receive events from eBPF programs using the linux
//! `perf` API.
//!
//! See [`PerfEventArray`] and [`AsyncPerfEventArray`].
#[cfg(any(
    feature = "async_tokio",
    feature = "async_std",
    feature = "async_compio"
))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async_tokio",
        feature = "async_std",
        feature = "async_compio"
    )))
)]
mod async_perf_event_array;
mod perf_buffer;
mod perf_event_array;

#[cfg(any(
    feature = "async_tokio",
    feature = "async_std",
    feature = "async_compio"
))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async_tokio",
        feature = "async_std",
        feature = "async_compio"
    )))
)]
pub use async_perf_event_array::*;
pub use perf_buffer::*;
pub use perf_event_array::*;
