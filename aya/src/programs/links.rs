use libc::{close, dup};
use std::{
    collections::{hash_map::Entry, HashMap},
    os::unix::prelude::RawFd,
};

use crate::{generated::bpf_attach_type, programs::ProgramError, sys::bpf_prog_detach};

pub(crate) trait Link: std::fmt::Debug + 'static {
    type Id: std::fmt::Debug + std::hash::Hash + Eq + PartialEq;

    fn id(&self) -> Self::Id;

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
}

impl<T: Link> Drop for LinkMap<T> {
    fn drop(&mut self) {
        for (_, link) in self.links.drain() {
            let _ = link.detach();
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) struct FdLinkId(pub(crate) RawFd);

#[derive(Debug)]
pub(crate) struct FdLink {
    fd: RawFd,
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

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) struct ProgAttachLinkId(RawFd, RawFd, bpf_attach_type);

#[derive(Debug)]
pub(crate) struct ProgAttachLink {
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
    ($wrapper:ident, #[$doc:meta] $wrapper_id:ident, $base:ident, $base_id:ident) => {
        #[$doc]
        #[derive(Debug, Hash, Eq, PartialEq)]
        pub struct $wrapper_id($base_id);

        #[derive(Debug)]
        pub(crate) struct $wrapper($base);

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

    use crate::programs::ProgramError;

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
}
