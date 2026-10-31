//! Cgroup programs and shared attachment and link definitions.

pub mod cgroup_device;
pub mod cgroup_skb;
pub mod cgroup_sock;
pub mod cgroup_sock_addr;
pub mod cgroup_sockopt;
pub mod cgroup_sysctl;
pub mod lsm_cgroup;
pub mod sock_ops;

macro_rules! define_cgroup_link {
    ($wrapper:ident, $wrapper_id:ident, $inner:ident, $inner_id:ident, $program:ident $(,)?) => {
        #[derive(Debug, Hash, Eq, PartialEq)]
        enum $inner_id {
            Fd(<$crate::programs::FdLink as $crate::programs::Link>::Id),
            ProgAttach(<$crate::programs::ProgAttachLink as $crate::programs::Link>::Id),
        }

        #[derive(Debug)]
        enum $inner {
            Fd($crate::programs::FdLink),
            ProgAttach($crate::programs::ProgAttachLink),
        }

        impl $crate::programs::Link for $inner {
            type Id = $inner_id;
            type Error = $crate::programs::ProgramError;

            fn id(&self) -> Self::Id {
                match self {
                    Self::Fd(link) => $inner_id::Fd(link.id()),
                    Self::ProgAttach(link) => $inner_id::ProgAttach(link.id()),
                }
            }

            fn detach(self) -> Result<(), Self::Error> {
                match self {
                    Self::Fd(link) => link.detach().map_err(Into::into),
                    Self::ProgAttach(link) => link.detach(),
                }
            }
        }

        $crate::programs::id_as_key!($inner, $inner_id);

        $crate::programs::define_link_wrapper!($wrapper, $wrapper_id, $inner, $inner_id, $program);
    };
}

pub(crate) use define_cgroup_link;

macro_rules! impl_cgroup_attach {
    ($link_id:ident, $inner:ident, self.$field:ident) => {
        $crate::programs::cgroup::impl_cgroup_attach!(
            @impl $link_id, $inner, [], |program| program.$field
        );
    };
    ($link_id:ident, $inner:ident, $arg:ident: $arg_ty:ty) => {
        $crate::programs::cgroup::impl_cgroup_attach!(
            @impl $link_id, $inner, [$arg: $arg_ty], |program| $arg
        );
    };
    ($link_id:ident, $inner:ident, $attach_type:path) => {
        $crate::programs::cgroup::impl_cgroup_attach!(
            @impl $link_id, $inner, [], |program| $attach_type
        );
    };
    (@impl $link_id:ident, $inner:ident, [$($arg:ident: $arg_ty:ty)?], |$program:ident| $attach_type:expr) => {
        /// Attaches the program to the given cgroup.
        ///
        /// The returned value can be used to detach, see [`Self::detach`].
        pub fn attach<T: std::os::fd::AsFd>(
            &mut self,
            cgroup: T,
            $($arg: $arg_ty,)?
            mode: $crate::programs::CgroupAttachMode,
        ) -> Result<$link_id, $crate::programs::ProgramError> {
            use std::os::fd::AsFd as _;

            use $crate::{
                programs::{FdLink, ProgAttachLink},
                sys::{LinkTarget, SyscallError, bpf_link_create},
                util::KernelVersion,
            };

            let $program = self;
            let attach_type: aya_obj::generated::bpf_attach_type = ($attach_type).into();
            let data = &mut $program.data;
            let prog_fd = data.fd()?.as_fd();
            let cgroup_fd = cgroup.as_fd();
            let link = if KernelVersion::at_least(5, 7, 0) {
                let link_fd = bpf_link_create(
                    prog_fd,
                    LinkTarget::Fd(cgroup_fd),
                    attach_type,
                    mode.into(),
                    None,
                )
                .map_err(|io_error| SyscallError {
                    call: "bpf_link_create",
                    io_error,
                })?;
                $inner::Fd(FdLink::new(link_fd))
            } else {
                let link = ProgAttachLink::attach(prog_fd, cgroup_fd, attach_type, mode)?;
                $inner::ProgAttach(link)
            };
            data.links.insert(link.into())
        }
    };
}

pub(crate) use impl_cgroup_attach;
