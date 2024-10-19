//! Probes and identifies available eBPF features supported by the host kernel.

use std::mem;

use aya_obj::generated::{bpf_attach_type, bpf_attr, bpf_insn, BPF_F_SLEEPABLE};
use libc::{E2BIG, EINVAL};

use super::{bpf_prog_load, SyscallError};
use crate::{programs::ProgramType, util::KernelVersion};

const RETURN_ZERO_INSNS: &[bpf_insn] = &[
    bpf_insn::new(0xb7, 0, 0, 0, 0), // mov64 r0 = 0
    bpf_insn::new(0x95, 0, 0, 0, 0), // exit
];
const GPL_COMPATIBLE: &[u8; 4] = b"GPL\0";

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
/// Returns [`SyscallError`] if kernel probing fails with an unexpected error.
///
/// Note that certain errors are expected and handled internally; only
/// unanticipated failures during probing will result in this error.
pub fn is_program_supported(program_type: ProgramType) -> Result<bool, SyscallError> {
    if program_type == ProgramType::Unspecified {
        return Ok(false);
    }

    // SAFETY: all-zero byte-pattern valid for `bpf_attr`
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    // SAFETY: union access
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    // `bpf_prog_load_fixup_attach_type()` sets this for us for cgroup_sock and
    // and sk_reuseport.
    let expected_attach_type = match program_type {
        ProgramType::CgroupSkb => Some(bpf_attach_type::BPF_CGROUP_INET_INGRESS),
        ProgramType::CgroupSockAddr => Some(bpf_attach_type::BPF_CGROUP_INET4_BIND),
        ProgramType::CgroupSockopt => Some(bpf_attach_type::BPF_CGROUP_GETSOCKOPT),
        ProgramType::SkLookup => Some(bpf_attach_type::BPF_SK_LOOKUP),
        ProgramType::Netfilter => Some(bpf_attach_type::BPF_NETFILTER),
        _ => None,
    };

    // Intentionally trigger `EINVAL` for some prog types, and use verifier
    // logs to help confirm whether the variant actually exists.
    let mut verifier_log = [0_u8; libc::PATH_MAX as usize];

    match program_type {
        ProgramType::KProbe => u.kern_version = KernelVersion::current().unwrap().code(),
        ProgramType::Tracing | ProgramType::Extension | ProgramType::Lsm => {
            u.log_buf = verifier_log.as_mut_ptr() as _;
            u.log_size = libc::PATH_MAX as _;
            u.log_level = 1;
        }
        ProgramType::Syscall => u.prog_flags = BPF_F_SLEEPABLE,
        _ => {}
    }

    u.prog_type = program_type as u32;
    u.insn_cnt = 2;
    u.insns = RETURN_ZERO_INSNS.as_ptr() as u64;
    u.license = GPL_COMPATIBLE.as_ptr() as u64;
    if let Some(expected_attach_type) = expected_attach_type {
        u.expected_attach_type = expected_attach_type as u32;
    }

    let io_error = match bpf_prog_load(&mut attr) {
        Ok(_) => return Ok(true),
        Err((_, io_error)) => io_error,
    };
    match io_error.raw_os_error() {
        Some(EINVAL) => {
            // verifier/`bpf_check_attach_target()` produces same log message
            // for these types (due to `attach_btf_id` unset)
            let supported = matches!(
                program_type, ProgramType::Tracing | ProgramType::Extension | ProgramType::Lsm
                if verifier_log.starts_with(b"Tracing programs must provide btf_id")
            );

            Ok(supported)
        }
        // `E2BIG` when accessing/using fields that are not available
        // e.g. `expected_attach_type`
        Some(E2BIG) => Ok(false),
        // `ENOTSUPP` from verifier/`check_struct_ops_btf_id()` for struct_ops
        Some(524) if program_type == ProgramType::StructOps => Ok(true),
        _ => Err(SyscallError {
            call: "bpf_prog_load",
            io_error,
        }),
    }
}
