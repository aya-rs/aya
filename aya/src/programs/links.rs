//! Program links.
use std::{
    ffi::CString,
    io,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, RawFd},
    path::{Path, PathBuf},
};

use aya_obj::generated::{
    BPF_F_AFTER, BPF_F_ALLOW_MULTI, BPF_F_ALLOW_OVERRIDE, BPF_F_BEFORE, BPF_F_ID, BPF_F_LINK,
    BPF_F_REPLACE, bpf_attach_type,
};
use hashbrown::hash_set::{Entry, HashSet};
use thiserror::Error;

use crate::{
    pin::PinError,
    programs::{MultiProgLink, MultiProgram, ProgramError, ProgramFd, ProgramId},
    sys::{SyscallError, bpf_get_object, bpf_pin_object, bpf_prog_attach, bpf_prog_detach},
};

/// A Link.
pub trait Link: std::fmt::Debug + Eq + std::hash::Hash + 'static {
    /// Unique Id
    type Id: std::fmt::Debug + Eq + std::hash::Hash + hashbrown::Equivalent<Self>;

    /// Returns the link id
    fn id(&self) -> Self::Id;

    /// Detaches the LinkOwnedLink is gone... but this doesn't work :(
    fn detach(self) -> Result<(), ProgramError>;
}

/// Program attachment mode.
#[derive(Clone, Copy, Debug, Default)]
pub enum CgroupAttachMode {
    /// Allows only one BPF program in the cgroup subtree.
    #[default]
    Single,

    /// Allows the program to be overridden by one in a sub-cgroup.
    AllowOverride,

    /// Allows multiple programs to be run in the cgroup subtree.
    AllowMultiple,
}

impl From<CgroupAttachMode> for u32 {
    fn from(mode: CgroupAttachMode) -> Self {
        match mode {
            CgroupAttachMode::Single => 0,
            CgroupAttachMode::AllowOverride => BPF_F_ALLOW_OVERRIDE,
            CgroupAttachMode::AllowMultiple => BPF_F_ALLOW_MULTI,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Links<T: Link> {
    links: HashSet<T>,
}

impl<T> Links<T>
where
    T: Eq + std::hash::Hash + Link,
    T::Id: hashbrown::Equivalent<T> + Eq + std::hash::Hash,
{
    pub(crate) fn new() -> Self {
        Self {
            links: Default::default(),
        }
    }

    pub(crate) fn insert(&mut self, link: T) -> Result<T::Id, ProgramError> {
        match self.links.entry(link) {
            Entry::Occupied(_entry) => Err(ProgramError::AlreadyAttached),
            Entry::Vacant(entry) => Ok(entry.insert().get().id()),
        }
    }

    pub(crate) fn remove(&mut self, link_id: T::Id) -> Result<(), ProgramError> {
        self.links
            .take(&link_id)
            .ok_or(ProgramError::NotAttached)?
            .detach()
    }

    pub(crate) fn forget(&mut self, link_id: T::Id) -> Result<T, ProgramError> {
        self.links.take(&link_id).ok_or(ProgramError::NotAttached)
    }
}

impl<T: Link> Links<T> {
    pub(crate) fn remove_all(&mut self) -> Result<(), ProgramError> {
        for link in self.links.drain() {
            link.detach()?;
        }
        Ok(())
    }
}

impl<T: Link> Drop for Links<T> {
    fn drop(&mut self) {
        let _ = self.remove_all();
    }
}

/// The identifier of an `FdLink`.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct FdLinkId(pub(crate) RawFd);

/// A file descriptor link.
///
/// Fd links are returned directly when attaching some program types (for
/// instance [`crate::programs::cgroup_skb::CgroupSkb`]), or can be obtained by
/// converting other link types (see the `TryFrom` implementations).
///
/// An important property of fd links is that they can be pinned. Pinning
/// can be used keep a link attached "in background" even after the program
/// that has created the link terminates.
///
/// # Example
///
/// ```no_run
/// # let mut bpf = Ebpf::load_file("ebpf_programs.o")?;
/// use aya::{Ebpf, programs::{links::FdLink, KProbe}};
///
/// let program: &mut KProbe = bpf.program_mut("intercept_wakeups").unwrap().try_into()?;
/// program.load()?;
/// let link_id = program.attach("try_to_wake_up", 0)?;
/// let link = program.take_link(link_id).unwrap();
/// let fd_link: FdLink = link.try_into().unwrap();
/// fd_link.pin("/sys/fs/bpf/intercept_wakeups_link").unwrap();
///
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[derive(Debug)]
pub struct FdLink {
    pub(crate) fd: crate::MockableFd,
}

impl FdLink {
    pub(crate) fn new(fd: crate::MockableFd) -> Self {
        Self { fd }
    }

    /// Pins the link to a BPF file system.
    ///
    /// When a link is pinned it will remain attached even after the link instance is dropped,
    /// and will only be detached once the pinned file is removed. To unpin, see [`PinnedLink::unpin()`].
    ///
    /// The parent directories in the provided path must already exist before calling this method,
    /// and must be on a BPF file system (bpffs).
    ///
    /// # Example
    /// ```no_run
    /// # use aya::programs::{links::FdLink, Extension};
    /// # use std::convert::TryInto;
    /// # #[derive(thiserror::Error, Debug)]
    /// # enum Error {
    /// #     #[error(transparent)]
    /// #     Ebpf(#[from] aya::EbpfError),
    /// #     #[error(transparent)]
    /// #     Pin(#[from] aya::pin::PinError),
    /// #     #[error(transparent)]
    /// #     Program(#[from] aya::programs::ProgramError)
    /// # }
    /// # let mut bpf = aya::Ebpf::load(&[])?;
    /// # let prog: &mut Extension = bpf.program_mut("example").unwrap().try_into()?;
    /// let link_id = prog.attach()?;
    /// let owned_link = prog.take_link(link_id)?;
    /// let fd_link: FdLink = owned_link.into();
    /// let pinned_link = fd_link.pin("/sys/fs/bpf/example")?;
    /// # Ok::<(), Error>(())
    /// ```
    pub fn pin<P: AsRef<Path>>(self, path: P) -> Result<PinnedLink, PinError> {
        use std::os::unix::ffi::OsStrExt as _;

        let path = path.as_ref();
        let path_string = CString::new(path.as_os_str().as_bytes()).map_err(|error| {
            PinError::InvalidPinPath {
                path: path.into(),
                error,
            }
        })?;
        bpf_pin_object(self.fd.as_fd(), &path_string).map_err(|io_error| SyscallError {
            call: "BPF_OBJ_PIN",
            io_error,
        })?;
        Ok(PinnedLink::new(path.into(), self))
    }
}

impl Link for FdLink {
    type Id = FdLinkId;

    fn id(&self) -> Self::Id {
        FdLinkId(self.fd.as_raw_fd())
    }

    fn detach(self) -> Result<(), ProgramError> {
        // detach is a noop since it consumes self. once self is consumed, drop will be triggered
        // and the link will be detached.
        //
        // Other links don't need to do this since they use define_link_wrapper!, but FdLink is a
        // bit special in that it defines a custom ::new() so it can't use the macro.
        Ok(())
    }
}

id_as_key!(FdLink, FdLinkId);

impl From<PinnedLink> for FdLink {
    fn from(p: PinnedLink) -> Self {
        p.inner
    }
}

/// A pinned file descriptor link.
///
/// This link has been pinned to the BPF filesystem. On drop, the file descriptor that backs
/// this link will be closed. Whether or not the program remains attached is dependent
/// on the presence of the file in BPFFS.
#[derive(Debug)]
pub struct PinnedLink {
    inner: FdLink,
    path: PathBuf,
}

impl PinnedLink {
    fn new(path: PathBuf, link: FdLink) -> Self {
        Self { inner: link, path }
    }

    /// Creates a [`crate::programs::links::PinnedLink`] from a valid path on bpffs.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<Self, LinkError> {
        use std::os::unix::ffi::OsStrExt as _;

        // TODO: avoid this unwrap by adding a new error variant.
        let path_string = CString::new(path.as_ref().as_os_str().as_bytes()).unwrap();
        let fd = bpf_get_object(&path_string).map_err(|io_error| {
            LinkError::SyscallError(SyscallError {
                call: "BPF_OBJ_GET",
                io_error,
            })
        })?;
        Ok(Self::new(path.as_ref().to_path_buf(), FdLink::new(fd)))
    }

    /// Removes the pinned link from the filesystem and returns an [`FdLink`].
    pub fn unpin(self) -> Result<FdLink, io::Error> {
        std::fs::remove_file(self.path)?;
        Ok(self.inner)
    }
}

/// The identifier of a `ProgAttachLink`.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct ProgAttachLinkId(RawFd, RawFd, bpf_attach_type);

/// The Link type used by programs that are attached with `bpf_prog_attach`.
#[derive(Debug)]
pub struct ProgAttachLink {
    prog_fd: ProgramFd,
    target_fd: crate::MockableFd,
    attach_type: bpf_attach_type,
}

impl ProgAttachLink {
    pub(crate) fn new(
        prog_fd: ProgramFd,
        target_fd: crate::MockableFd,
        attach_type: bpf_attach_type,
    ) -> Self {
        Self {
            prog_fd,
            target_fd,
            attach_type,
        }
    }

    pub(crate) fn attach(
        prog_fd: BorrowedFd<'_>,
        target_fd: BorrowedFd<'_>,
        attach_type: bpf_attach_type,
        mode: CgroupAttachMode,
    ) -> Result<Self, ProgramError> {
        // The link is going to own this new file descriptor so we are
        // going to need a duplicate whose lifetime we manage. Let's
        // duplicate it prior to attaching it so the new file
        // descriptor is closed at drop in case it fails to attach.
        let prog_fd = prog_fd.try_clone_to_owned()?;
        let prog_fd = crate::MockableFd::from_fd(prog_fd);
        let target_fd = target_fd.try_clone_to_owned()?;
        let target_fd = crate::MockableFd::from_fd(target_fd);
        bpf_prog_attach(prog_fd.as_fd(), target_fd.as_fd(), attach_type, mode.into())?;

        let prog_fd = ProgramFd(prog_fd);
        Ok(Self {
            prog_fd,
            target_fd,
            attach_type,
        })
    }
}

impl Link for ProgAttachLink {
    type Id = ProgAttachLinkId;

    fn id(&self) -> Self::Id {
        ProgAttachLinkId(
            self.prog_fd.as_fd().as_raw_fd(),
            self.target_fd.as_raw_fd(),
            self.attach_type,
        )
    }

    fn detach(self) -> Result<(), ProgramError> {
        bpf_prog_detach(
            self.prog_fd.as_fd(),
            self.target_fd.as_fd(),
            self.attach_type,
        )
        .map_err(Into::into)
    }
}

id_as_key!(ProgAttachLink, ProgAttachLinkId);

macro_rules! id_as_key {
    ($wrapper:ident, $wrapper_id:ident) => {
        impl PartialEq for $wrapper {
            fn eq(&self, other: &Self) -> bool {
                use $crate::programs::links::Link as _;

                self.id() == other.id()
            }
        }

        impl Eq for $wrapper {}

        impl std::hash::Hash for $wrapper {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                use $crate::programs::links::Link as _;

                self.id().hash(state)
            }
        }

        impl hashbrown::Equivalent<$wrapper> for $wrapper_id {
            fn equivalent(&self, key: &$wrapper) -> bool {
                use $crate::programs::links::Link as _;

                *self == key.id()
            }
        }
    };
}

pub(crate) use id_as_key;

macro_rules! define_link_wrapper {
    (#[$doc1:meta] $wrapper:ident, #[$doc2:meta] $wrapper_id:ident, $base:ident, $base_id:ident, $program:ident,) => {
        #[$doc2]
        #[derive(Debug, Hash, Eq, PartialEq)]
        pub struct $wrapper_id($base_id);

        #[$doc1]
        #[derive(Debug)]
        pub struct $wrapper(Option<$base>);

        #[allow(dead_code)]
        // allow dead code since currently XDP/TC are the only consumers of inner and
        // into_inner
        impl $wrapper {
            fn new(base: $base) -> $wrapper {
                $wrapper(Some(base))
            }

            fn inner(&self) -> &$base {
                self.0.as_ref().unwrap()
            }

            fn into_inner(mut self) -> $base {
                self.0.take().unwrap()
            }
        }

        impl Drop for $wrapper {
            fn drop(&mut self) {
                use $crate::programs::links::Link as _;

                if let Some(base) = self.0.take() {
                    let _ = base.detach();
                }
            }
        }

        impl $crate::programs::Link for $wrapper {
            type Id = $wrapper_id;

            fn id(&self) -> Self::Id {
                $wrapper_id(self.0.as_ref().unwrap().id())
            }

            fn detach(mut self) -> Result<(), ProgramError> {
                self.0.take().unwrap().detach()
            }
        }

        $crate::programs::links::id_as_key!($wrapper, $wrapper_id);

        impl From<$base> for $wrapper {
            fn from(b: $base) -> $wrapper {
                $wrapper(Some(b))
            }
        }

        impl From<$wrapper> for $base {
            fn from(mut w: $wrapper) -> $base {
                w.0.take().unwrap()
            }
        }

        impl $program {
            /// Detaches the program.
            ///
            /// See [`Self::attach`].
            pub fn detach(&mut self, link_id: $wrapper_id) -> Result<(), ProgramError> {
                self.data.links.remove(link_id)
            }

            /// Takes ownership of the link referenced by the provided `link_id`.
            ///
            /// The caller takes the responsibility of managing the lifetime of the link. When the
            /// returned [`$wrapper`] is dropped, the link is detached.
            pub fn take_link(&mut self, link_id: $wrapper_id) -> Result<$wrapper, ProgramError> {
                self.data.links.forget(link_id)
            }
        }
    };
}

pub(crate) use define_link_wrapper;

#[derive(Error, Debug)]
/// Errors from operations on links.
pub enum LinkError {
    /// Invalid link.
    #[error("Invalid link")]
    InvalidLink,
    /// Syscall failed.
    #[error(transparent)]
    SyscallError(#[from] SyscallError),
}

#[derive(Debug)]
pub(crate) enum LinkRef {
    Id(u32),
    Fd(RawFd),
}

bitflags::bitflags! {
    /// Flags which are use to build a set of MprogOptions.
    #[derive(Clone, Copy, Debug, Default)]
    pub(crate) struct MprogFlags: u32 {
        const REPLACE = BPF_F_REPLACE;
        const BEFORE = BPF_F_BEFORE;
        const AFTER = BPF_F_AFTER;
        const ID = BPF_F_ID;
        const LINK = BPF_F_LINK;
    }
}

/// Arguments required for interacting with the kernel's multi-prog API.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 6.6.0.
///
/// # Example
///
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::programs::{tc, SchedClassifier, TcAttachType, tc::TcAttachOptions, LinkOrder};
///
/// let prog: &mut SchedClassifier = bpf.program_mut("redirect_ingress").unwrap().try_into()?;
/// prog.load()?;
/// let options = TcAttachOptions::TcxOrder(LinkOrder::first());
/// prog.attach_with_options("eth0", TcAttachType::Ingress, options)?;
///
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[derive(Debug)]
pub struct LinkOrder {
    pub(crate) link_ref: LinkRef,
    pub(crate) flags: MprogFlags,
}

/// Ensure that default link ordering is to be attached last.
impl Default for LinkOrder {
    fn default() -> Self {
        Self {
            link_ref: LinkRef::Fd(0),
            flags: MprogFlags::AFTER,
        }
    }
}

impl LinkOrder {
    /// Attach before all other links.
    pub fn first() -> Self {
        Self {
            link_ref: LinkRef::Id(0),
            flags: MprogFlags::BEFORE,
        }
    }

    /// Attach after all other links.
    pub fn last() -> Self {
        Self {
            link_ref: LinkRef::Id(0),
            flags: MprogFlags::AFTER,
        }
    }

    /// Attach before the given link.
    pub fn before_link<L: MultiProgLink>(link: &L) -> Result<Self, LinkError> {
        Ok(Self {
            link_ref: LinkRef::Fd(link.fd()?.as_raw_fd()),
            flags: MprogFlags::BEFORE | MprogFlags::LINK,
        })
    }

    /// Attach after the given link.
    pub fn after_link<L: MultiProgLink>(link: &L) -> Result<Self, LinkError> {
        Ok(Self {
            link_ref: LinkRef::Fd(link.fd()?.as_raw_fd()),
            flags: MprogFlags::AFTER | MprogFlags::LINK,
        })
    }

    /// Attach before the given program.
    pub fn before_program<P: MultiProgram>(program: &P) -> Result<Self, ProgramError> {
        Ok(Self {
            link_ref: LinkRef::Fd(program.fd()?.as_raw_fd()),
            flags: MprogFlags::BEFORE,
        })
    }

    /// Attach after the given program.
    pub fn after_program<P: MultiProgram>(program: &P) -> Result<Self, ProgramError> {
        Ok(Self {
            link_ref: LinkRef::Fd(program.fd()?.as_raw_fd()),
            flags: MprogFlags::AFTER,
        })
    }

    /// Attach before the program with the given id.
    pub fn before_program_id(id: ProgramId) -> Self {
        Self {
            link_ref: LinkRef::Id(id.0),
            flags: MprogFlags::BEFORE | MprogFlags::ID,
        }
    }

    /// Attach after the program with the given id.
    pub fn after_program_id(id: ProgramId) -> Self {
        Self {
            link_ref: LinkRef::Id(id.0),
            flags: MprogFlags::AFTER | MprogFlags::ID,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, fs::File, rc::Rc};

    use assert_matches::assert_matches;
    use aya_obj::generated::{BPF_F_ALLOW_MULTI, BPF_F_ALLOW_OVERRIDE};
    use tempfile::tempdir;

    use super::{FdLink, Link, Links};
    use crate::{
        programs::{CgroupAttachMode, ProgramError},
        sys::override_syscall,
    };

    #[derive(Debug, Hash, Eq, PartialEq)]
    struct TestLinkId(u8, u8);

    #[derive(Debug)]
    struct TestLink {
        id: (u8, u8),
        detached: Rc<RefCell<u8>>,
    }

    impl TestLink {
        fn new(a: u8, b: u8) -> Self {
            Self {
                id: (a, b),
                detached: Rc::new(RefCell::new(0)),
            }
        }
    }

    impl Link for TestLink {
        type Id = TestLinkId;

        fn id(&self) -> Self::Id {
            TestLinkId(self.id.0, self.id.1)
        }

        fn detach(self) -> Result<(), ProgramError> {
            *self.detached.borrow_mut() += 1;
            Ok(())
        }
    }

    id_as_key!(TestLink, TestLinkId);

    #[test]
    fn test_link_map() {
        let mut links = Links::new();
        let l1 = TestLink::new(1, 2);
        let l1_detached = Rc::clone(&l1.detached);
        let l2 = TestLink::new(1, 3);
        let l2_detached = Rc::clone(&l2.detached);

        let id1 = links.insert(l1).unwrap();
        let id2 = links.insert(l2).unwrap();

        assert_eq!(*l1_detached.borrow(), 0);
        assert_eq!(*l2_detached.borrow(), 0);

        links.remove(id1).unwrap();
        assert_eq!(*l1_detached.borrow(), 1);
        assert_eq!(*l2_detached.borrow(), 0);

        links.remove(id2).unwrap();
        assert_eq!(*l1_detached.borrow(), 1);
        assert_eq!(*l2_detached.borrow(), 1);
    }

    #[test]
    fn test_already_attached() {
        let mut links = Links::new();

        links.insert(TestLink::new(1, 2)).unwrap();
        assert_matches!(
            links.insert(TestLink::new(1, 2)),
            Err(ProgramError::AlreadyAttached)
        );
    }

    #[test]
    fn test_not_attached() {
        let mut links = Links::new();

        let l1 = TestLink::new(1, 2);
        let l1_id1 = l1.id();
        let l1_id2 = l1.id();
        links.insert(TestLink::new(1, 2)).unwrap();
        links.remove(l1_id1).unwrap();
        assert_matches!(links.remove(l1_id2), Err(ProgramError::NotAttached));
    }

    #[test]
    fn test_drop_detach() {
        let l1 = TestLink::new(1, 2);
        let l1_detached = Rc::clone(&l1.detached);
        let l2 = TestLink::new(1, 3);
        let l2_detached = Rc::clone(&l2.detached);

        {
            let mut links = Links::new();
            let id1 = links.insert(l1).unwrap();
            links.insert(l2).unwrap();
            // manually remove one link
            links.remove(id1).unwrap();
            assert_eq!(*l1_detached.borrow(), 1);
            assert_eq!(*l2_detached.borrow(), 0);
        }
        // remove the other on drop
        assert_eq!(*l1_detached.borrow(), 1);
        assert_eq!(*l2_detached.borrow(), 1);
    }

    #[test]
    fn test_owned_detach() {
        let l1 = TestLink::new(1, 2);
        let l1_detached = Rc::clone(&l1.detached);
        let l2 = TestLink::new(1, 3);
        let l2_detached = Rc::clone(&l2.detached);

        let owned_l1 = {
            let mut links = Links::new();
            let id1 = links.insert(l1).unwrap();
            links.insert(l2).unwrap();
            // manually forget one link
            let owned_l1 = links.forget(id1);
            assert_eq!(*l1_detached.borrow(), 0);
            assert_eq!(*l2_detached.borrow(), 0);
            owned_l1.unwrap()
        };

        // l2 is detached on `Drop`, but l1 is still alive
        assert_eq!(*l1_detached.borrow(), 0);
        assert_eq!(*l2_detached.borrow(), 1);

        // manually detach l1
        owned_l1.detach().unwrap();
        assert_eq!(*l1_detached.borrow(), 1);
        assert_eq!(*l2_detached.borrow(), 1);
    }

    #[test]
    #[cfg_attr(miri, ignore = "`mkdir` not available when isolation is enabled")]
    fn test_pin() {
        let dir = tempdir().unwrap();
        let f1 = File::create(dir.path().join("f1")).expect("unable to create file in tmpdir");
        let fd_link = FdLink::new(f1.into());

        // override syscall to allow for pin to happen in our tmpdir
        override_syscall(|_| Ok(0));
        // create the file that would have happened as a side-effect of a real pin operation
        let pin = dir.path().join("f1-pin");
        File::create(&pin).expect("unable to create file in tmpdir");
        assert!(pin.exists());

        let pinned_link = fd_link.pin(&pin).expect("pin failed");
        pinned_link.unpin().expect("unpin failed");
        assert!(!pin.exists());
    }

    #[test]
    fn test_cgroup_attach_flag() {
        assert_eq!(u32::from(CgroupAttachMode::Single), 0);
        assert_eq!(
            u32::from(CgroupAttachMode::AllowOverride),
            BPF_F_ALLOW_OVERRIDE
        );
        assert_eq!(
            u32::from(CgroupAttachMode::AllowMultiple),
            BPF_F_ALLOW_MULTI
        );
    }
}
