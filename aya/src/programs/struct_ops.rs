//! Struct ops programs.

use aya_obj::generated::bpf_prog_type::BPF_PROG_TYPE_STRUCT_OPS;

use crate::programs::{
    FdLink, FdLinkId, ProgramData, ProgramError, ProgramType, define_link_wrapper, load_program,
};

/// A program that implements a kernel struct ops interface.
///
/// Struct ops programs are used to implement kernel-defined structures
/// containing function pointers, such as `sched_ext_ops` for custom
/// schedulers. Individual struct ops programs correspond to methods
/// in the kernel struct.
///
/// Unlike most program types, struct ops programs are not individually
/// attached. Instead, they are associated with a struct ops map that
/// is created and attached as a unit. Use [`Ebpf::attach_struct_ops`]
/// to attach the struct ops map after loading.
///
/// [`Ebpf::attach_struct_ops`]: crate::Ebpf::attach_struct_ops
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.3.
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_STRUCT_OPS")]
pub struct StructOps {
    pub(crate) data: ProgramData<StructOpsLink>,
}

impl StructOps {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::StructOps;

    /// Loads the program inside the kernel.
    ///
    /// Struct ops programs use `attach_btf_id` to identify the function
    /// prototype in the kernel BTF.
    pub fn load(&mut self, attach_btf_id: u32) -> Result<(), ProgramError> {
        self.data.attach_btf_id = Some(attach_btf_id);
        load_program(BPF_PROG_TYPE_STRUCT_OPS, &mut self.data)
    }
}

define_link_wrapper!(StructOpsLink, StructOpsLinkId, FdLink, FdLinkId, StructOps);

impl StructOpsLink {
    pub(crate) const fn wrap(base: FdLink) -> Self {
        Self(Some(base))
    }
}
