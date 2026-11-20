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
//! [kernel documentation of BPF token]: https://github.com/torvalds/linux/blob/a38297e3f/include/uapi/linux/bpf.h#L876-L904

use std::os::fd::{AsFd, BorrowedFd};

use crate::sys::{SyscallError, bpf_token_create};

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
/// # Example
///
/// ```no_run
/// use std::fs::File;
///
/// use aya::token::BpfToken;
///
/// // A bpffs instance owned by the current user namespace and mounted with
/// // delegation options, e.g. by a container runtime.
/// let bpffs = File::open("/sys/fs/bpf")?;
/// let token = BpfToken::create(bpffs, 0)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// [`bpf_token_create`]: https://github.com/torvalds/linux/blob/a38297e3f/kernel/bpf/token.c#L112-L231
#[derive(Debug)]
#[doc(alias = "bpf_token")]
pub struct BpfToken(crate::MockableFd);

impl BpfToken {
    /// Creates a BPF token from the root directory of a bpffs instance.
    ///
    /// `bpffs` must be a file descriptor for the root directory of a bpffs
    /// mount, opened without `O_PATH`: the kernel looks it up with
    /// [`fdget`], which ignores `O_PATH` files, and fails with `EBADF`. This
    /// rules out the detached mount returned by `fsmount(2)`, which is an
    /// `O_PATH` file descriptor; reopen it with `openat(mnt_fd, ".", O_RDONLY)`.
    ///
    /// `flags` is passed to the kernel as is. No flags are defined yet, and the
    /// kernel rejects any non-zero value with [`EINVAL`].
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel refuses to create the token, for
    /// example with `ENOENT` if the bpffs instance delegates nothing or with
    /// `EOPNOTSUPP` if the caller is in the initial user namespace.
    ///
    /// [`fdget`]: https://github.com/torvalds/linux/blob/a38297e3f/fs/file.c#L1157-L1160
    /// [`EINVAL`]: https://github.com/torvalds/linux/blob/a38297e3f/kernel/bpf/syscall.c#L5614-L5616
    #[doc(alias = "BPF_TOKEN_CREATE")]
    pub fn create<Fd: AsFd>(bpffs: Fd, flags: u32) -> Result<Self, SyscallError> {
        let fd = bpf_token_create(bpffs.as_fd(), flags).map_err(|io_error| SyscallError {
            call: "bpf_token_create",
            io_error,
        })?;
        Ok(Self(fd))
    }
}

impl AsFd for BpfToken {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
