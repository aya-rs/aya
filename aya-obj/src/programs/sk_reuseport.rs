//! `BPF_PROG_TYPE_SK_REUSEPORT` program bindings.

use crate::generated::bpf_attach_type;

/// Attach types for `BPF_PROG_TYPE_SK_REUSEPORT` programs.
#[derive(Clone, Copy, Debug)]
pub enum SkReuseportAttachType {
    /// Select a socket for a new packet or connection.
    Select,
    /// Select a socket for a new packet or connection, or migrate an
    /// in-flight request to another listener in the reuseport group.
    SelectOrMigrate,
}

impl From<SkReuseportAttachType> for bpf_attach_type {
    fn from(value: SkReuseportAttachType) -> Self {
        match value {
            SkReuseportAttachType::Select => Self::BPF_SK_REUSEPORT_SELECT,
            SkReuseportAttachType::SelectOrMigrate => Self::BPF_SK_REUSEPORT_SELECT_OR_MIGRATE,
        }
    }
}
