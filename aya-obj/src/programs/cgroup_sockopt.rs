//! Cgroup socket option programs.
use alloc::{borrow::ToOwned, string::String};

use crate::generated::bpf_attach_type;

#[cfg(not(feature = "std"))]
use crate::std;

/// Defines where to attach a `CgroupSockopt` program.
#[derive(Copy, Clone, Debug)]
pub enum CgroupSockoptAttachType {
    /// Attach to GetSockopt.
    Get,
    /// Attach to SetSockopt.
    Set,
}

impl From<CgroupSockoptAttachType> for bpf_attach_type {
    fn from(s: CgroupSockoptAttachType) -> bpf_attach_type {
        match s {
            CgroupSockoptAttachType::Get => bpf_attach_type::BPF_CGROUP_GETSOCKOPT,
            CgroupSockoptAttachType::Set => bpf_attach_type::BPF_CGROUP_SETSOCKOPT,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0} is not a valid attach type for a CGROUP_SOCKOPT program")]
pub(crate) struct InvalidAttachType(String);

impl CgroupSockoptAttachType {
    pub(crate) fn try_from(value: &str) -> Result<CgroupSockoptAttachType, InvalidAttachType> {
        match value {
            "getsockopt" => Ok(CgroupSockoptAttachType::Get),
            "setsockopt" => Ok(CgroupSockoptAttachType::Set),
            _ => Err(InvalidAttachType(value.to_owned())),
        }
    }
}
