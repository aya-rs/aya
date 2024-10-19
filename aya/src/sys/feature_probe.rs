//! Probes and identifies available eBPF features supported by the host kernel.

use std::io::ErrorKind;

use aya_obj::{
    btf::{Btf, BtfError, BtfKind},
    generated::{BPF_F_SLEEPABLE, bpf_attach_type},
};
use libc::{E2BIG, EINVAL};

use super::{SyscallError, bpf_prog_load, with_trivial_prog};
use crate::{
    programs::{ProgramError, ProgramType},
    util::KernelVersion,
};

/// Whether the host kernel supports the [`ProgramType`].
///
/// # Examples
///
/// ```no_run
/// # use aya::{
/// #     programs::ProgramType,
/// #     sys::feature_probe::is_program_supported,
/// # };
/// #
/// match is_program_supported(ProgramType::Xdp) {
///     Ok(true) => println!("XDP supported :)"),
///     Ok(false) => println!("XDP not supported :("),
///     Err(err) => println!("Uh oh! Unexpected error: {:?}", err),
/// }
/// ```
///
/// # Errors
///
/// Returns [`ProgramError::SyscallError`] if a syscall fails with an unexpected
/// error, or [`ProgramError::Btf`] for BTF related errors.
///
/// Certain errors are expected and handled internally; only unanticipated
/// failures during probing will result in these errors.
pub fn is_program_supported(program_type: ProgramType) -> Result<bool, ProgramError> {
    if program_type == ProgramType::Unspecified {
        return Ok(false);
    }

    let mut verifier_log = match program_type {
        ProgramType::Extension => vec![0_u8; libc::PATH_MAX as usize],
        _ => vec![],
    };
    let error = match create_minimal_program(program_type, &mut verifier_log) {
        Ok(_) => return Ok(true),
        Err(err) => err,
    };
    match error {
        ProgramError::SyscallError(err) if matches!(err.io_error.raw_os_error(), Some(EINVAL)) => {
            // verifier/`bpf_check_attach_target()` produces same log message
            // for these types due to unset `attach_btf_id`
            let supported = program_type == ProgramType::Extension
                && verifier_log.starts_with(b"Tracing programs must provide btf_id");
            Ok(supported)
        }
        ProgramError::SyscallError(err) if matches!(err.io_error.raw_os_error(), Some(E2BIG)) => {
            Ok(false)
        }
        ProgramError::SyscallError(err)
            // `ENOTSUPP` from verifier/`check_struct_ops_btf_id()` for struct_ops
            if matches!(err.io_error.raw_os_error(), Some(524))
                && program_type == ProgramType::StructOps =>
        {
            Ok(true)
        }
        ProgramError::Btf(BtfError::FileError { error, .. })
            if error.kind() == ErrorKind::NotFound =>
        {
            Ok(false)
        }
        _ => Err(error),
    }
}

/// Create a minimal program with the specified type.
/// Types not created for `Extension` and `StructOps`.
fn create_minimal_program(
    program_type: ProgramType,
    verifier_log: &mut [u8],
) -> Result<crate::MockableFd, ProgramError> {
    with_trivial_prog(|attr| {
        // SAFETY: union access
        let u = unsafe { &mut attr.__bindgen_anon_3 };

        // `bpf_prog_load_fixup_attach_type()` sets this for us for cgroup_sock and
        // and sk_reuseport.
        let expected_attach_type = match program_type {
            ProgramType::CgroupSkb => Some(bpf_attach_type::BPF_CGROUP_INET_INGRESS),
            ProgramType::CgroupSockAddr => Some(bpf_attach_type::BPF_CGROUP_INET4_BIND),
            ProgramType::CgroupSockopt => Some(bpf_attach_type::BPF_CGROUP_GETSOCKOPT),
            ProgramType::Tracing => Some(bpf_attach_type::BPF_TRACE_FENTRY),
            ProgramType::Lsm => Some(bpf_attach_type::BPF_LSM_MAC),
            ProgramType::SkLookup => Some(bpf_attach_type::BPF_SK_LOOKUP),
            ProgramType::Netfilter => Some(bpf_attach_type::BPF_NETFILTER),
            _ => None,
        };

        match program_type {
            ProgramType::KProbe => u.kern_version = KernelVersion::current().unwrap().code(),
            ProgramType::Tracing | ProgramType::Lsm => {
                let btf = Btf::from_sys_fs()?;
                let func_name = match program_type {
                    ProgramType::Tracing => "bpf_fentry_test1",
                    _ => "bpf_lsm_bpf",
                };
                u.attach_btf_id = btf.id_by_type_name_kind(func_name, BtfKind::Func)?;
            }
            ProgramType::Extension => {
                u.log_buf = verifier_log.as_mut_ptr() as u64;
                u.log_level = 1;
                u.log_size = verifier_log.len() as u32;
            }
            ProgramType::Syscall => u.prog_flags = BPF_F_SLEEPABLE,
            _ => {}
        }

        u.prog_type = program_type as u32;
        if let Some(expected_attach_type) = expected_attach_type {
            u.expected_attach_type = expected_attach_type as u32;
        }

        bpf_prog_load(attr).map_err(|io_error| {
            ProgramError::SyscallError(SyscallError {
                call: "bpf_prog_load",
                io_error,
            })
        })
    })
}
