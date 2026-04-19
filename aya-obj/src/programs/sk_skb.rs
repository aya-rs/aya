//! Sk skb programs.
use crate::generated::bpf_attach_type;

/// Defines the kind of a `SkSkb` program.
#[derive(Copy, Clone, Debug)]
pub enum SkSkbKind {
    /// A Stream Parser
    StreamParser,
    /// A Stream Verdict
    StreamVerdict,
}

impl From<SkSkbKind> for bpf_attach_type {
    fn from(s: SkSkbKind) -> Self {
        match s {
            SkSkbKind::StreamParser => Self::BPF_SK_SKB_STREAM_PARSER,
            SkSkbKind::StreamVerdict => Self::BPF_SK_SKB_STREAM_VERDICT,
        }
    }
}
