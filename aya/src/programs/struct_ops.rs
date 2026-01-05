//! struct_ops programs.

use aya_obj::{
    btf::{Btf, BtfKind},
    generated::{bpf_attach_type::BPF_STRUCT_OPS, bpf_prog_type::BPF_PROG_TYPE_STRUCT_OPS},
};

use crate::programs::{
    define_link_wrapper, load_program, FdLink, FdLinkId, ProgramData, ProgramError, ProgramType,
};

/// A program that implements a kernel struct_ops interface.
///
/// Struct ops programs are used to implement kernel interfaces like `sched_ext_ops` for
/// custom schedulers or `hid_bpf_ops` for HID device handling. Unlike other BPF program
/// types, struct_ops programs are callbacks that the kernel invokes when specific
/// operations are needed.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.6.
///
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     BtfError(#[from] aya::BtfError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Ebpf(#[from] aya::EbpfError),
/// # }
/// # let mut bpf = Ebpf::load_file("ebpf_programs.o")?;
/// use aya::{Ebpf, programs::StructOps, Btf};
///
/// let btf = Btf::from_sys_fs()?;
/// let program: &mut StructOps = bpf.program_mut("my_struct_ops").unwrap().try_into()?;
/// program.load("hid_bpf_ops", &btf)?;
/// # Ok::<(), Error>(())
/// ```
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
    /// # Arguments
    ///
    /// * `struct_name` - the name of the struct_ops type (e.g., "hid_bpf_ops",
    ///   "sched_ext_ops")
    /// * `btf` - the BTF information for the running kernel
    pub fn load(&mut self, struct_name: &str, btf: &Btf) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(BPF_STRUCT_OPS);
        self.data.attach_btf_id = Some(btf.id_by_type_name_kind(struct_name, BtfKind::Struct)?);
        load_program(BPF_PROG_TYPE_STRUCT_OPS, &mut self.data)
    }
}

define_link_wrapper!(StructOpsLink, StructOpsLinkId, FdLink, FdLinkId, StructOps);
