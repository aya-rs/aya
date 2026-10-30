//! BPF tokens.
//!
//! A BPF token lets a process use the subset of BPF functionality delegated
//! by a BPF filesystem (bpffs) instance without holding the corresponding
//! capabilities in the initial user namespace.
//!
//! Delegation is configured by a privileged process through the bpffs mount
//! options `delegate_cmds`, `delegate_maps`, `delegate_progs` and
//! `delegate_attachs`; see the [kernel documentation of BPF token].
//!
//! The kernel only creates a token in the user namespace that owns the bpffs
//! instance, which must not be the initial user namespace. Setting up a token
//! therefore takes two processes:
//!
//! 1. The process that will use the token creates a bpffs context with
//!    [`create_bpffs_context`] from inside its user namespace, and hands it to a
//!    privileged process, e.g. over a Unix socket.
//! 2. The privileged process sets the delegation options and mounts the
//!    context with [`mount_delegated_bpffs`], and hands the mount back.
//! 3. The first process creates the token with [`BpfToken::create`].
//!
//! [kernel documentation of BPF token]: https://github.com/torvalds/linux/blob/a38297e3f/include/uapi/linux/bpf.h#L876-L904

use std::{
    ffi::CString,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use aya_obj::generated::{bpf_attach_type, bpf_cmd, bpf_prog_type};

use crate::{
    maps::MapType,
    programs::ProgramType,
    sys::{
        SyscallError, bpf_token_create,
        mount::{fsconfig_create, fsconfig_set_string, fsmount, fsopen},
    },
};

/// A BPF command, such as `BPF_MAP_CREATE` or `BPF_PROG_LOAD`.
#[doc(alias = "bpf_cmd")]
pub type BpfCommand = bpf_cmd;

/// A BPF token.
///
/// A token is created from the root of a bpffs instance and carries the
/// delegation options of that instance.
///
/// The kernel only creates tokens for processes in the user namespace that
/// owns the bpffs instance, and never in the initial user namespace; see
/// [`bpf_token_create`]. The bpffs instance is therefore typically created
/// with `fsopen(2)` from inside the target user namespace, then configured
/// and mounted by a privileged process.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 6.9.
///
/// [`bpf_token_create`]: https://github.com/torvalds/linux/blob/a38297e3f/kernel/bpf/token.c#L112-L231
#[derive(Debug)]
#[doc(alias = "BPF_TOKEN_CREATE")]
pub struct BpfToken(crate::MockableFd);

impl BpfToken {
    /// Creates a BPF token from the root directory of a bpffs instance.
    ///
    /// `bpffs` must be a file descriptor for the root directory of a bpffs
    /// mount, opened without `O_PATH`. A detached mount returned by
    /// `fsmount(2)` can be reopened with `openat(mnt_fd, ".", O_RDONLY)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel refuses to create the token, for
    /// example with `ENOENT` if the bpffs instance delegates nothing or with
    /// `EOPNOTSUPP` if the caller is in the initial user namespace.
    pub fn create<Fd: AsFd>(bpffs: Fd) -> Result<Self, SyscallError> {
        let fd = bpf_token_create(bpffs.as_fd()).map_err(|io_error| SyscallError {
            call: "bpf_token_create",
            io_error,
        })?;
        Ok(Self(fd))
    }
}

impl AsFd for BpfToken {
    fn as_fd(&self) -> BorrowedFd<'_> {
        let Self(fd) = self;
        fd.as_fd()
    }
}

/// The BPF functionality delegated by a bpffs instance.
///
/// Each set corresponds to one of the `delegate_cmds`, `delegate_maps`,
/// `delegate_progs` and `delegate_attachs` mount options. No token can be
/// created from an instance that delegates nothing.
///
/// # Example
///
/// ```
/// use aya::{
///     maps::MapType,
///     programs::{CgroupSkbAttachType, ProgramType},
///     token::{BpfCommand, BpffsDelegation},
/// };
///
/// let mut delegation = BpffsDelegation::default();
/// delegation
///     .command(BpfCommand::BPF_MAP_CREATE)
///     .command(BpfCommand::BPF_PROG_LOAD)
///     .map_type(MapType::Array)
///     .program_type(ProgramType::CgroupSkb)
///     .attach_type(CgroupSkbAttachType::Ingress);
/// ```
#[derive(Clone, Debug, Default)]
pub struct BpffsDelegation {
    commands: u64,
    map_types: u64,
    program_types: u64,
    attach_types: u64,
}

impl BpffsDelegation {
    /// Delegates a BPF command.
    pub const fn command(&mut self, command: BpfCommand) -> &mut Self {
        self.commands |= bit(command as u32);
        self
    }

    /// Delegates all BPF commands.
    pub const fn all_commands(&mut self) -> &mut Self {
        self.commands = u64::MAX;
        self
    }

    /// Delegates the creation of maps of the given type.
    pub const fn map_type(&mut self, map_type: MapType) -> &mut Self {
        self.map_types |= bit(map_type as u32);
        self
    }

    /// Delegates the creation of maps of all types.
    pub const fn all_map_types(&mut self) -> &mut Self {
        self.map_types = u64::MAX;
        self
    }

    /// Delegates the loading of programs of the given type.
    pub fn program_type(&mut self, program_type: ProgramType) -> &mut Self {
        self.program_types |= bit(bpf_prog_type::from(program_type) as u32);
        self
    }

    /// Delegates the loading of programs of all types.
    pub const fn all_program_types(&mut self) -> &mut Self {
        self.program_types = u64::MAX;
        self
    }

    /// Delegates the loading of programs with the given expected attach type.
    ///
    /// The kernel checks the expected attach type of every program loaded
    /// through a token, including programs without one, for which it is 0
    /// (`BPF_CGROUP_INET_INGRESS`); see [`bpf_token_allow_prog_type`].
    ///
    /// [`bpf_token_allow_prog_type`]: https://github.com/torvalds/linux/blob/a38297e3f/kernel/bpf/token.c#L269-L278
    pub fn attach_type<A: Into<bpf_attach_type>>(&mut self, attach_type: A) -> &mut Self {
        self.attach_types |= bit(attach_type.into() as u32);
        self
    }

    /// Delegates the loading of programs with all expected attach types.
    pub const fn all_attach_types(&mut self) -> &mut Self {
        self.attach_types = u64::MAX;
        self
    }
}

const fn bit(value: u32) -> u64 {
    match 1u64.checked_shl(value) {
        Some(bit) => bit,
        None => 0,
    }
}

/// Creates a bpffs context with `fsopen(2)`.
///
/// The context belongs to the user namespace of the caller, which is where
/// tokens can later be created from the mounted instance. Pass the returned
/// file descriptor to a privileged process that calls
/// [`mount_delegated_bpffs`].
///
/// # Minimum kernel version
///
/// Creating a bpffs context outside of the initial user namespace requires
/// Linux 6.9.
pub fn create_bpffs_context() -> Result<OwnedFd, SyscallError> {
    fsopen(c"bpf").map_err(|io_error| SyscallError {
        call: "fsopen",
        io_error,
    })
}

/// Sets the delegation options of a bpffs context, then creates and mounts it.
///
/// `context` is typically created by [`create_bpffs_context`] in the user
/// namespace that will use the tokens. Setting delegation options requires
/// `CAP_SYS_ADMIN` in the initial user namespace.
///
/// Returns the file descriptor of the resulting detached mount, as returned by
/// `fsmount(2)`. It can be attached in the mount namespace of the process that
/// created the context with `move_mount(2)`, e.g. at `/sys/fs/bpf`, or handed
/// back to that process, which then creates a token with [`BpfToken::create`]
/// from `openat(mount_fd, ".", O_RDONLY)`. The mount is released when its last
/// file descriptor is closed, unless it was attached.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 6.9.
pub fn mount_delegated_bpffs<Fd: AsFd>(
    context: Fd,
    delegation: &BpffsDelegation,
) -> Result<OwnedFd, SyscallError> {
    let context = context.as_fd();
    let BpffsDelegation {
        commands,
        map_types,
        program_types,
        attach_types,
    } = delegation;
    for (option, mask) in [
        (c"delegate_cmds", commands),
        (c"delegate_maps", map_types),
        (c"delegate_progs", program_types),
        (c"delegate_attachs", attach_types),
    ] {
        if *mask == 0 {
            continue;
        }
        let value = CString::new(format!("{mask:#x}")).unwrap();
        fsconfig_set_string(context, option, &value).map_err(|io_error| SyscallError {
            call: "fsconfig",
            io_error,
        })?;
    }
    fsconfig_create(context).map_err(|io_error| SyscallError {
        call: "fsconfig",
        io_error,
    })?;
    fsmount(context).map_err(|io_error| SyscallError {
        call: "fsmount",
        io_error,
    })
}
