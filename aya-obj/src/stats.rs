//! BPF stats type for `BPF_ENABLE_STATS`

use crate::generated::bpf_stats_type;

/// The type of BPF statistic to enable.
#[derive(Copy, Clone, Debug)]
pub enum BpfStatsType {
    /// Metrics for `run_time_ns` and `run_cnt`.
    RunTime,
}

impl From<BpfStatsType> for bpf_stats_type {
    fn from(value: BpfStatsType) -> Self {
        match value {
            BpfStatsType::RunTime => bpf_stats_type::BPF_STATS_RUN_TIME,
        }
    }
}
