//! Program links.
use libc::{close, dup};
use thiserror::Error;

use std::{
    collections::{hash_map::Entry, HashMap},
    ffi::CString,
    io,
    os::unix::prelude::RawFd,
    path::{Path, PathBuf},
};

use crate::{
    generated::bpf_attach_type,
    pin::PinError,
    programs::ProgramError,
    sys::{bpf_get_object, bpf_pin_object, bpf_prog_detach},
};

/// A Link.
pub trait Link: std::fmt::Debug + 'static {
    /// Unique Id
    type Id: std::fmt::Debug + std::hash::Hash + Eq + PartialEq;

    /// Returns the link id
    fn id(&self) -> Self::Id;

    /// Detaches the LinkOwnedLink is gone... but this doesn't work :(
    fn detach(self) -> Result<(), ProgramError>;
}

#[derive(Debug)]
pub(crate) struct LinkMap<T: Link> {
    links: HashMap<T::Id, T>,
}

impl<T: Link> LinkMap<T> {
    pub(crate) fn new() -> LinkMap<T> {
        LinkMap {
            links: HashMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, link: T) -> Result<T::Id, ProgramError> {
        let id = link.id();

        match self.links.entry(link.id()) {
            Entry::Occupied(_) => return Err(ProgramError::AlreadyAttached),
            Entry::Vacant(e) => e.insert(link),
        };

        Ok(id)
    }

    pub(crate) fn remove(&mut self, link_id: T::Id) -> Result<(), ProgramError> {
        self.links
            .remove(&link_id)
            .ok_or(ProgramError::NotAttached)?
            .detach()
    }

    pub(crate) fn remove_all(&mut self) -> Result<(), ProgramError> {
        for (_, link) in self.links.drain() {
            link.detach()?;
        }
        Ok(())
    }

    pub(crate) fn forget(&mut self, link_id: T::Id) -> Result<T, ProgramError> {
        self.links.remove(&link_id).ok_or(ProgramError::NotAttached)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> + ExactSizeIterator {
        self.links.values()
    }
}

impl<T: Link> Drop for LinkMap<T> {
    fn drop(&mut self) {
        let _ = self.remove_all();
    }
}

/// The identifier of an `FdLink`.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct FdLinkId(pub(crate) RawFd);

/// A file descriptor link.
#[derive(Debug)]
pub struct FdLink {
    pub(crate) fd: RawFd,
}

impl FdLink {
    pub(crate) fn new(fd: RawFd) -> FdLink {
        FdLink { fd }
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
    /// #     Bpf(#[from] aya::BpfError),
    /// #     #[error(transparent)]
    /// #     Pin(#[from] aya::pin::PinError),
    /// #     #[error(transparent)]
    /// #     Program(#[from] aya::programs::ProgramError)
    /// # }
    /// # let mut bpf = aya::Bpf::load(&[])?;
    /// # let prog: &mut Extension = bpf.program_mut("example").unwrap().try_into()?;
    /// let link_id = prog.attach()?;
    /// let owned_link = prog.take_link(link_id)?;
    /// let fd_link: FdLink = owned_link.into();
    /// let pinned_link = fd_link.pin("/sys/fs/bpf/example")?;
    /// # Ok::<(), Error>(())
    /// ```
    pub fn pin<P: AsRef<Path>>(self, path: P) -> Result<PinnedLink, PinError> {
        let path_string =
            CString::new(path.as_ref().to_string_lossy().into_owned()).map_err(|e| {
                PinError::InvalidPinPath {
                    error: e.to_string(),
                }
            })?;
        bpf_pin_object(self.fd, &path_string).map_err(|(_, io_error)| PinError::SyscallError {
            name: "BPF_OBJ_PIN".to_string(),
            io_error,
        })?;
        Ok(PinnedLink::new(PathBuf::from(path.as_ref()), self))
    }
}

impl Link for FdLink {
    type Id = FdLinkId;

    fn id(&self) -> Self::Id {
        FdLinkId(self.fd)
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

impl From<PinnedLink> for FdLink {
    fn from(p: PinnedLink) -> Self {
        p.inner
    }
}

impl Drop for FdLink {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
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
        PinnedLink { inner: link, path }
    }

    /// Creates a [`PinnedLink`] from a valid path on bpffs.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<Self, LinkError> {
        let path_string = CString::new(path.as_ref().to_string_lossy().to_string()).unwrap();
        let fd =
            bpf_get_object(&path_string).map_err(|(code, io_error)| LinkError::SyscallError {
                call: "BPF_OBJ_GET".to_string(),
                code,
                io_error,
            })? as RawFd;
        Ok(PinnedLink::new(
            path.as_ref().to_path_buf(),
            FdLink::new(fd),
        ))
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
    prog_fd: RawFd,
    target_fd: RawFd,
    attach_type: bpf_attach_type,
}

impl ProgAttachLink {
    pub(crate) fn new(
        prog_fd: RawFd,
        target_fd: RawFd,
        attach_type: bpf_attach_type,
    ) -> ProgAttachLink {
        ProgAttachLink {
            prog_fd,
            target_fd: unsafe { dup(target_fd) },
            attach_type,
        }
    }
}

impl Link for ProgAttachLink {
    type Id = ProgAttachLinkId;

    fn id(&self) -> Self::Id {
        ProgAttachLinkId(self.prog_fd, self.target_fd, self.attach_type)
    }

    fn detach(self) -> Result<(), ProgramError> {
        let _ = bpf_prog_detach(self.prog_fd, self.target_fd, self.attach_type);
        unsafe { close(self.target_fd) };
        Ok(())
    }
}

macro_rules! define_link_wrapper {
    (#[$doc1:meta] $wrapper:ident, #[$doc2:meta] $wrapper_id:ident, $base:ident, $base_id:ident) => {
        #[$doc2]
        #[derive(Debug, Hash, Eq, PartialEq)]
        pub struct $wrapper_id($base_id);

        #[$doc1]
        #[derive(Debug)]
        pub struct $wrapper(Option<$base>);

        #[allow(dead_code)]
        // allow dead code since currently XDP is the only consumer of inner and
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
                use crate::programs::links::Link;

                if let Some(base) = self.0.take() {
                    let _ = base.detach();
                }
            }
        }

        impl crate::programs::Link for $wrapper {
            type Id = $wrapper_id;

            fn id(&self) -> Self::Id {
                $wrapper_id(self.0.as_ref().unwrap().id())
            }

            fn detach(mut self) -> Result<(), ProgramError> {
                self.0.take().unwrap().detach()
            }
        }

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
    #[error("the `{call}` syscall failed with code {code}")]
    SyscallError {
        /// Syscall Name.
        call: String,
        /// Error code.
        code: libc::c_long,
        #[source]
        /// Original io::Error.
        io_error: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, env, fs::File, mem, os::unix::io::AsRawFd, rc::Rc};

    use crate::{programs::ProgramError, sys::override_syscall};

    use super::{FdLink, Link, LinkMap};

    #[derive(Debug, Hash, Eq, PartialEq)]
    struct TestLinkId(u8, u8);

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestLink {
        id: (u8, u8),
        detached: Rc<RefCell<u8>>,
    }

    impl TestLink {
        fn new(a: u8, b: u8) -> TestLink {
            TestLink {
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

    #[test]
    fn test_link_map() {
        let mut links = LinkMap::new();
        let l1 = TestLink::new(1, 2);
        let l1_detached = Rc::clone(&l1.detached);
        let l2 = TestLink::new(1, 3);
        let l2_detached = Rc::clone(&l2.detached);

        let id1 = links.insert(l1).unwrap();
        let id2 = links.insert(l2).unwrap();

        assert!(*l1_detached.borrow() == 0);
        assert!(*l2_detached.borrow() == 0);

        assert!(links.remove(id1).is_ok());
        assert!(*l1_detached.borrow() == 1);
        assert!(*l2_detached.borrow() == 0);

        assert!(links.remove(id2).is_ok());
        assert!(*l1_detached.borrow() == 1);
        assert!(*l2_detached.borrow() == 1);
    }

    #[test]
    fn test_iter() {
        let mut links = LinkMap::new();
        let l1 = TestLink::new(1, 2);
        let l2 = TestLink::new(1, 3);

        let l1_copy = l1.clone();
        let l2_copy = l2.clone();

        let _id1 = links.insert(l1).unwrap();
        let _id2 = links.insert(l2).unwrap();

        assert_eq!(links.iter().len(), 2);

        let collected: Vec<&TestLink> = links.iter().collect();
        let expected: Vec<&TestLink> = vec![&l1_copy, &l2_copy];

        assert_eq!(collected, expected);
    }

    #[test]
    fn test_already_attached() {
        let mut links = LinkMap::new();

        links.insert(TestLink::new(1, 2)).unwrap();
        assert!(matches!(
            links.insert(TestLink::new(1, 2)),
            Err(ProgramError::AlreadyAttached)
        ));
    }

    #[test]
    fn test_not_attached() {
        let mut links = LinkMap::new();

        let l1 = TestLink::new(1, 2);
        let l1_id1 = l1.id();
        let l1_id2 = l1.id();
        links.insert(TestLink::new(1, 2)).unwrap();
        links.remove(l1_id1).unwrap();
        assert!(matches!(
            links.remove(l1_id2),
            Err(ProgramError::NotAttached)
        ));
    }

    #[test]
    fn test_drop_detach() {
        let l1 = TestLink::new(1, 2);
        let l1_detached = Rc::clone(&l1.detached);
        let l2 = TestLink::new(1, 3);
        let l2_detached = Rc::clone(&l2.detached);

        {
            let mut links = LinkMap::new();
            let id1 = links.insert(l1).unwrap();
            links.insert(l2).unwrap();
            // manually remove one link
            assert!(links.remove(id1).is_ok());
            assert!(*l1_detached.borrow() == 1);
            assert!(*l2_detached.borrow() == 0);
        }
        // remove the other on drop
        assert!(*l1_detached.borrow() == 1);
        assert!(*l2_detached.borrow() == 1);
    }

    #[test]
    fn test_owned_detach() {
        let l1 = TestLink::new(1, 2);
        let l1_detached = Rc::clone(&l1.detached);
        let l2 = TestLink::new(1, 3);
        let l2_detached = Rc::clone(&l2.detached);

        let owned_l1 = {
            let mut links = LinkMap::new();
            let id1 = links.insert(l1).unwrap();
            links.insert(l2).unwrap();
            // manually forget one link
            let owned_l1 = links.forget(id1);
            assert!(*l1_detached.borrow() == 0);
            assert!(*l2_detached.borrow() == 0);
            owned_l1.unwrap()
        };

        // l2 is detached on `Drop`, but l1 is still alive
        assert!(*l1_detached.borrow() == 0);
        assert!(*l2_detached.borrow() == 1);

        // manually detach l1
        assert!(owned_l1.detach().is_ok());
        assert!(*l1_detached.borrow() == 1);
        assert!(*l2_detached.borrow() == 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_pin() {
        let dir = env::temp_dir();
        let f1 = File::create(dir.join("f1")).expect("unable to create file in tmpdir");
        let fd_link = FdLink::new(f1.as_raw_fd());

        // leak the fd, it will get closed when our pinned link is dropped
        mem::forget(f1);

        // override syscall to allow for pin to happen in our tmpdir
        override_syscall(|_| Ok(0));
        // create the file that would have happened as a side-effect of a real pin operation
        File::create(dir.join("f1-pin")).expect("unable to create file in tmpdir");
        assert!(dir.join("f1-pin").exists());

        let pinned_link = fd_link.pin(dir.join("f1-pin")).expect("pin failed");
        pinned_link.unpin().expect("unpin failed");
        assert!(!dir.join("f1-pin").exists());
    }
}
