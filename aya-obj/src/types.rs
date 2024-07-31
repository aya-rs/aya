//! Idiomatic Rust wrappers around BPF types.

/// The type of BPF statistic to enable.
#[non_exhaustive]
#[doc(alias = "bpf_stats_type")]
#[derive(Copy, Clone, Debug)]
pub enum StatsType {
    /// Metrics for `run_time_ns` and `run_cnt`.
    #[doc(alias = "BPF_STATS_RUN_TIME")]
    RunTime,
}

impl From<StatsType> for crate::generated::bpf_stats_type {
    fn from(value: StatsType) -> Self {
        use crate::generated::bpf_stats_type::*;

        match value {
            StatsType::RunTime => BPF_STATS_RUN_TIME,
        }
    }
}
