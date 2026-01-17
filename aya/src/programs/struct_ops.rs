//! struct_ops programs.

use aya_obj::{
    btf::{Btf, BtfKind},
    generated::{bpf_attach_type, bpf_prog_type::BPF_PROG_TYPE_STRUCT_OPS},
};
use log::debug;

use crate::programs::{
    FdLink, FdLinkId, Link, ProgramData, ProgramError, ProgramType, links::id_as_key, load_program,
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
    /// The struct member name this program implements (from section name)
    pub(crate) member_name: String,
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
    ///
    /// The member name is automatically determined from the program's section name
    /// (e.g., `struct_ops/hid_device_event` -> `hid_device_event`).
    pub fn load(&mut self, struct_name: &str, btf: &Btf) -> Result<(), ProgramError> {
        let struct_type_id = btf.id_by_type_name_kind(struct_name, BtfKind::Struct)?;
        let member_index = btf.struct_member_index(struct_type_id, &self.member_name)?;

        debug!(
            "loading struct_ops program member='{}' struct='{struct_name}' member_index={member_index}",
            self.member_name
        );

        // For struct_ops, expected_attach_type stores the member index (not a bpf_attach_type).
        // SAFETY: While this creates a technically invalid enum value, it is safe because:
        // 1. bpf_attach_type is #[repr(u32)] so it has the same memory layout as u32
        // 2. The value is only used by casting back to u32 in bpf_load_program()
        // 3. The kernel interprets this field as a raw u32 for struct_ops programs
        // A cleaner solution would require adding a separate field to ProgramData.
        self.data.expected_attach_type =
            Some(unsafe { std::mem::transmute::<u32, bpf_attach_type>(member_index) });
        self.data.attach_btf_id = Some(struct_type_id);
        load_program(BPF_PROG_TYPE_STRUCT_OPS, &mut self.data)
    }

    /// Returns the struct member name this program implements.
    pub fn member_name(&self) -> &str {
        &self.member_name
    }
}

/// The identifier for a [`StructOpsLink`].
///
/// This is returned by [`StructOpsMap::attach`](crate::maps::StructOpsMap::attach).
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct StructOpsLinkId(FdLinkId);

/// The link used by [`StructOps`] programs.
///
/// This is created by [`StructOpsMap::attach`](crate::maps::StructOpsMap::attach)
/// after the struct_ops map has been registered.
#[derive(Debug)]
pub struct StructOpsLink(Option<FdLink>);

#[allow(dead_code)]
impl StructOpsLink {
    pub(crate) fn new(base: FdLink) -> Self {
        Self(Some(base))
    }

    fn inner(&self) -> &FdLink {
        self.0.as_ref().unwrap()
    }

    fn into_inner(mut self) -> FdLink {
        self.0.take().unwrap()
    }
}

impl Drop for StructOpsLink {
    fn drop(&mut self) {
        if let Some(base) = self.0.take() {
            let _: Result<(), ProgramError> = base.detach();
        }
    }
}

impl Link for StructOpsLink {
    type Id = StructOpsLinkId;

    fn id(&self) -> Self::Id {
        StructOpsLinkId(self.0.as_ref().unwrap().id())
    }

    fn detach(mut self) -> Result<(), ProgramError> {
        self.0.take().unwrap().detach()
    }
}

id_as_key!(StructOpsLink, StructOpsLinkId);

impl From<FdLink> for StructOpsLink {
    fn from(b: FdLink) -> Self {
        Self(Some(b))
    }
}

impl From<StructOpsLink> for FdLink {
    fn from(mut w: StructOpsLink) -> Self {
        w.0.take().unwrap()
    }
}
