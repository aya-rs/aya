//! Program links.
use libc::{close, dup};

use std::{
    borrow::Borrow,
    collections::{hash_map::Entry, HashMap},
    ops::Deref,
    os::unix::prelude::RawFd,
};

use crate::{generated::bpf_attach_type, programs::ProgramError, sys::bpf_prog_detach};

/// A Link.
pub trait Link: std::fmt::Debug + 'static {
    /// Unique Id
    type Id: std::fmt::Debug + std::hash::Hash + Eq + PartialEq;

    /// Returns the link id
    fn id(&self) -> Self::Id;

    /// Detaches the Link
    fn detach(self) -> Result<(), ProgramError>;
}

/// An owned link that automatically detaches the inner link when dropped.
pub struct OwnedLink<T: Link> {
    inner: Option<T>,
}

impl<T: Link> OwnedLink<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self { inner: Some(inner) }
    }
}

impl<T: Link> Deref for OwnedLink<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner.borrow().as_ref().unwrap()
    }
}

impl<T: Link> Drop for OwnedLink<T> {
    fn drop(&mut self) {
        if let Some(link) = self.inner.take() {
            link.detach().unwrap();
        }
    }
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
}

impl Link for FdLink {
    type Id = FdLinkId;

    fn id(&self) -> Self::Id {
        FdLinkId(self.fd)
    }

    fn detach(self) -> Result<(), ProgramError> {
        unsafe { close(self.fd) };
        Ok(())
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
        pub struct $wrapper($base);

        impl crate::programs::Link for $wrapper {
            type Id = $wrapper_id;

            fn id(&self) -> Self::Id {
                $wrapper_id(self.0.id())
            }

            fn detach(self) -> Result<(), ProgramError> {
                self.0.detach()
            }
        }

        impl From<$base> for $wrapper {
            fn from(b: $base) -> $wrapper {
                $wrapper(b)
            }
        }
    };
}

pub(crate) use define_link_wrapper;

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use crate::programs::{OwnedLink, ProgramError};

    use super::{Link, LinkMap};

    #[derive(Debug, Hash, Eq, PartialEq)]
    struct TestLinkId(u8, u8);

    #[derive(Debug)]
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
    fn test_owned_drop() {
        let l1 = TestLink::new(1, 2);
        let l1_detached = Rc::clone(&l1.detached);
        let l2 = TestLink::new(1, 3);
        let l2_detached = Rc::clone(&l2.detached);

        {
            let mut links = LinkMap::new();
            let id1 = links.insert(l1).unwrap();
            links.insert(l2).unwrap();

            // manually forget one link and wrap in OwnedLink
            let _ = OwnedLink {
                inner: Some(links.forget(id1).unwrap()),
            };

            // OwnedLink was dropped in the statement above
            assert!(*l1_detached.borrow() == 1);
            assert!(*l2_detached.borrow() == 0);
        };

        assert!(*l1_detached.borrow() == 1);
        assert!(*l2_detached.borrow() == 1);
    }
}
