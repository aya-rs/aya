//! Cgroup skb programs.

use std::path::Path;

use aya_obj::generated::bpf_prog_type::BPF_PROG_TYPE_CGROUP_SKB;
pub use aya_obj::programs::CgroupSkbAttachType;

use crate::{
    VerifierLogLevel,
    programs::{
        ProgramData, ProgramError, ProgramType,
        cgroup::{define_cgroup_link, impl_cgroup_attach},
        impl_try_into_fdlink, load_program,
    },
};

/// A program used to inspect or filter network activity for a given cgroup.
///
/// [`CgroupSkb`] programs can be used to inspect or filter network activity
/// generated on all the sockets belonging to a given [cgroup]. They can be
/// attached to both _ingress_ and _egress_.
///
/// [cgroup]: https://man7.org/linux/man-pages/man7/cgroups.7.html
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.10.
///
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     IO(#[from] std::io::Error),
/// #     #[error(transparent)]
/// #     Map(#[from] aya::maps::MapError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use std::fs::File;
/// use aya::programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let egress: &mut CgroupSkb = bpf.program_mut("egress_filter").unwrap().try_into()?;
/// egress.load()?;
/// egress.attach(file, CgroupSkbAttachType::Egress, CgroupAttachMode::Single)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_SKB")]
pub struct CgroupSkb {
    pub(crate) data: ProgramData<CgroupSkbLink>,
    pub(crate) attach_type: Option<CgroupSkbAttachType>,
}

impl CgroupSkb {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::CgroupSkb;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data, attach_type } = self;
        load_program(BPF_PROG_TYPE_CGROUP_SKB, attach_type.map(Into::into), data)
    }

    /// Returns the expected attach type of the program.
    ///
    /// [`CgroupSkb`] programs can specify the expected attach type in their ELF
    /// section name, eg `cgroup_skb/ingress` or `cgroup_skb/egress`. This
    /// method returns `None` for programs defined with the generic section
    /// `cgroup/skb`.
    pub const fn expected_attach_type(&self) -> &Option<CgroupSkbAttachType> {
        &self.attach_type
    }

    impl_cgroup_attach!(CgroupSkbLinkId, CgroupSkbLinkInner, attach_type: CgroupSkbAttachType);

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(
        path: P,
        expected_attach_type: CgroupSkbAttachType,
    ) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self {
            data,
            attach_type: Some(expected_attach_type),
        })
    }
}

define_cgroup_link!(
    CgroupSkbLink,
    CgroupSkbLinkId,
    CgroupSkbLinkInner,
    CgroupSkbLinkIdInner,
    CgroupSkb,
);

impl_try_into_fdlink!(CgroupSkbLink, CgroupSkbLinkInner);
