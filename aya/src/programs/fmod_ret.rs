//! Function return modification programs.

use aya_obj::{
    btf::{Btf, BtfKind},
    generated::{bpf_attach_type::BPF_MODIFY_RETURN, bpf_prog_type::BPF_PROG_TYPE_TRACING},
};

use crate::programs::{
    FdLink, FdLinkId, ProgramData, ProgramError, ProgramType, define_link_wrapper,
    load_program_with_attach_type, utils::attach_raw_tracepoint,
};

/// A program that can replace a kernel function's return value before it runs.
///
/// Returning zero lets the target function run. A nonzero return skips the target
/// and supplies its result in the target's return type. The
/// [`fmod_ret`](https://docs.rs/aya-ebpf/latest/aya_ebpf/macros/attr.fmod_ret.html)
/// macro sign-extends `i32` results to preserve negative errors for `long` targets.
/// Attached fexit programs still run and see that return value. The target must
/// support return modification through an entry in the error-injection list, a
/// registration in a BTF fmodret ID set, or a `security_` name. BTF fmodret ID sets
/// are supported from Linux 6.2. Error-injection annotations populate the list only
/// when `CONFIG_FUNCTION_ERROR_INJECTION` is enabled.
/// Other verifier and trampoline restrictions still apply.
///
/// These rules are not documented by the kernel; see
/// [`invoke_bpf_mod_ret`](https://github.com/torvalds/linux/blob/0c3836482/arch/x86/net/bpf_jit_comp.c#L2678-L2713)
/// and the [target eligibility checks](https://github.com/torvalds/linux/blob/7d0a66e4b/kernel/bpf/verifier.c#L23830-L23844).
/// Section names are documented in the [kernel's program type table].
///
/// [kernel's program type table]: https://docs.kernel.org/bpf/libbpf/program_types.html
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.7 (arm64: 6.4).
///
/// # Test runs
///
/// [`TestRun`](crate::programs::TestRun) invokes the kernel's fixed
/// `bpf_modify_return_test*` sequence, not the target passed to [`Self::load`].
/// Verify a map side effect to prove a program attached to a test target ran.
///
/// # Examples
///
/// ```no_run
/// use aya::{Btf, Ebpf, programs::FModRet};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut bpf = Ebpf::load_file("programs.o")?;
/// let program: &mut FModRet = bpf.program_mut("deny_send").unwrap().try_into()?;
/// program.load("security_socket_sendmsg", &Btf::from_sys_fs()?)?;
/// program.attach()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_MODIFY_RETURN")]
#[doc(alias = "BPF_PROG_TYPE_TRACING")]
pub struct FModRet {
    pub(crate) data: ProgramData<FModRetLink>,
}

impl FModRet {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::Tracing;

    /// Loads the program for the kernel function `fn_name`.
    ///
    /// `btf` must describe the running kernel. The kernel validates whether the
    /// target permits return modification.
    pub fn load(&mut self, fn_name: &str, btf: &Btf) -> Result<(), ProgramError> {
        self.data.attach_btf_id = Some(btf.id_by_type_name_kind(fn_name, BtfKind::Func)?);
        load_program_with_attach_type(BPF_PROG_TYPE_TRACING, BPF_MODIFY_RETURN, &mut self.data)
    }

    /// Attaches the program. The returned ID can be used with [`Self::detach`].
    pub fn attach(&mut self) -> Result<FModRetLinkId, ProgramError> {
        attach_raw_tracepoint(&mut self.data, None)
    }
}

define_link_wrapper!(FModRetLink, FModRetLinkId, FdLink, FdLinkId, FModRet);
