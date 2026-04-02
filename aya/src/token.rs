//! BPF token support for unprivileged BPF operations.
//!
//! BPF tokens (Linux 6.9+) allow unprivileged userspace programs to perform BPF
//! operations by obtaining a token from a specially-configured BPF filesystem.
//!
//! # Overview
//!
//! The typical flow for using BPF tokens:
//!
//! 1. A privileged process creates a BPF filesystem with delegation options using
//!    [`create_bpf_filesystem`].
//! 2. An unprivileged process creates a [`BpfToken`] from that filesystem.
//! 3. The token is passed to [`EbpfLoader::token`](crate::EbpfLoader::token) to load
//!    BPF programs and maps.

use std::{
    ffi::{CStr, CString},
    io,
    os::{
        fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd},
        unix::ffi::OsStrExt as _,
    },
    path::Path,
};

use aya_obj::{
    attach::BpfAttachType,
    cmd::BpfCommand,
    generated::{bpf_attach_type, bpf_cmd, bpf_map_type, bpf_prog_type},
    maps::BpfMapType,
    programs::BpfProgType,
};

use crate::sys::bpf_token_create;

/// A BPF token obtained from a BPF filesystem.
///
/// BPF tokens delegate a subset of BPF capabilities to unprivileged processes.
/// The token is created from a BPF filesystem (bpffs) that has been mounted with
/// appropriate `delegate_*` mount options.
///
/// # Minimum kernel version
///
/// BPF tokens require Linux 6.9 or later.
///
/// # Example
///
/// ```no_run
/// use aya::{Ebpf, EbpfLoader};
/// use aya::token::BpfToken;
///
/// let token = BpfToken::create("/sys/fs/bpf")?;
/// let bpf = EbpfLoader::new()
///     .token(&token)
///     .load_file("program.o")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct BpfToken {
    fd: crate::MockableFd,
}

impl BpfToken {
    /// Creates a BPF token from the given BPF filesystem path.
    ///
    /// The path must point to a mounted bpffs with the desired `delegate_*` options.
    pub fn create<P: AsRef<Path>>(bpffs_path: P) -> Result<Self, io::Error> {
        let path = bpffs_path.as_ref();
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // Open the bpffs directory.
        let dir_fd = unsafe { libc::open(path_c.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY) };
        if dir_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let dir_fd = unsafe { OwnedFd::from_raw_fd(dir_fd) };

        let token_fd = bpf_token_create(dir_fd.as_fd())?;
        Ok(Self { fd: token_fd })
    }

    /// Returns a borrowed file descriptor for this token.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Permissions for a BPF filesystem that control what operations are delegated
/// to unprivileged processes via BPF tokens.
///
/// Use [`FilesystemPermissionsBuilder`] to construct an instance.
#[derive(Debug, Default)]
pub struct FilesystemPermissions {
    delegate_cmds: u64,
    delegate_maps: u64,
    delegate_progs: u64,
    delegate_attachs: u64,
    uid: Option<u32>,
    gid: Option<u32>,
}

/// Builder for [`FilesystemPermissions`].
///
/// # Example
///
/// ```no_run
/// use aya::token::{FilesystemPermissionsBuilder, create_bpf_filesystem};
/// use aya_obj::cmd::BpfCommand;
/// use aya_obj::programs::BpfProgType;
/// use aya_obj::maps::BpfMapType;
///
/// let perms = FilesystemPermissionsBuilder::default()
///     .allow_cmd(BpfCommand::MapCreate)
///     .allow_cmd(BpfCommand::ProgLoad)
///     .allow_prog_type(BpfProgType::SocketFilter)
///     .allow_map_type(BpfMapType::Array)
///     .uid(1000)
///     .build();
///
/// create_bpf_filesystem("/my/bpffs", perms)?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug, Default)]
pub struct FilesystemPermissionsBuilder {
    perms: FilesystemPermissions,
}

impl FilesystemPermissionsBuilder {
    /// Allows the given BPF command to be used by token holders.
    #[must_use]
    pub fn allow_cmd(mut self, cmd: BpfCommand) -> Self {
        let cmd: bpf_cmd = cmd.into();
        self.perms.delegate_cmds |= 1 << (cmd as u64);
        self
    }

    /// Allows the given map type to be created by token holders.
    #[must_use]
    pub fn allow_map_type(mut self, map_type: BpfMapType) -> Self {
        let map_type: bpf_map_type = map_type.into();
        self.perms.delegate_maps |= 1 << (map_type as u64);
        self
    }

    /// Allows the given program type to be loaded by token holders.
    #[must_use]
    pub fn allow_prog_type(mut self, prog_type: BpfProgType) -> Self {
        let prog_type: bpf_prog_type = prog_type.into();
        self.perms.delegate_progs |= 1 << (prog_type as u64);
        self
    }

    /// Allows the given attach type to be used by token holders.
    #[must_use]
    pub fn allow_attach_type(mut self, attach_type: BpfAttachType) -> Self {
        let attach_type: bpf_attach_type = attach_type.into();
        self.perms.delegate_attachs |= 1 << (attach_type as u64);
        self
    }

    /// Sets the owner UID of the mounted filesystem.
    #[must_use]
    pub const fn uid(mut self, uid: u32) -> Self {
        self.perms.uid = Some(uid);
        self
    }

    /// Sets the owner GID of the mounted filesystem.
    #[must_use]
    pub const fn gid(mut self, gid: u32) -> Self {
        self.perms.gid = Some(gid);
        self
    }

    /// Builds the [`FilesystemPermissions`].
    #[must_use]
    pub const fn build(self) -> FilesystemPermissions {
        self.perms
    }
}

// fsopen/fsconfig/fsmount/move_mount syscall numbers
// These are stable and architecture-independent on Linux 5.2+.
const SYS_FSOPEN: libc::c_long = libc::SYS_fsopen;
const SYS_FSCONFIG: libc::c_long = libc::SYS_fsconfig;
const SYS_FSMOUNT: libc::c_long = libc::SYS_fsmount;
const SYS_MOVE_MOUNT: libc::c_long = libc::SYS_move_mount;

const FSCONFIG_SET_STRING: u32 = 1;
const FSCONFIG_CMD_CREATE: u32 = 6;
const FSMOUNT_CLOEXEC: u32 = 1;
const MOVE_MOUNT_F_EMPTY_PATH: u32 = 4;

/// Creates and mounts a BPF filesystem with the given delegation permissions.
///
/// This uses the new mount API (`fsopen`/`fsconfig`/`fsmount`/`move_mount`)
/// which requires Linux 5.2+. Since BPF tokens require Linux 6.9+, this is
/// always available when tokens are.
///
/// The caller must have `CAP_SYS_ADMIN` to mount the filesystem. After mounting,
/// unprivileged processes can create tokens from the resulting filesystem.
///
/// # Example
///
/// ```no_run
/// use aya::token::{FilesystemPermissionsBuilder, create_bpf_filesystem};
/// use aya_obj::cmd::BpfCommand;
///
/// let perms = FilesystemPermissionsBuilder::default()
///     .allow_cmd(BpfCommand::MapCreate)
///     .allow_cmd(BpfCommand::ProgLoad)
///     .allow_cmd(BpfCommand::BtfLoad)
///     .uid(1000)
///     .build();
///
/// create_bpf_filesystem("/my/bpffs", perms)?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn create_bpf_filesystem<P: AsRef<Path>>(
    path: P,
    perms: FilesystemPermissions,
) -> Result<(), io::Error> {
    let path = path.as_ref();
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let bpf_fs = c"bpf";

    // fsopen("bpf", FSOPEN_CLOEXEC)
    let fs_fd = unsafe {
        libc::syscall(SYS_FSOPEN, bpf_fs.as_ptr(), 1u32 /* FSOPEN_CLOEXEC */)
    };
    if fs_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fs_fd = unsafe { OwnedFd::from_raw_fd(fs_fd as i32) };

    // Helper to call fsconfig with a string value.
    let fsconfig_set_string = |key: &CStr, value: &CStr| -> io::Result<()> {
        let ret = unsafe {
            libc::syscall(
                SYS_FSCONFIG,
                fs_fd.as_raw_fd(),
                FSCONFIG_SET_STRING,
                key.as_ptr(),
                value.as_ptr(),
                0,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    };

    // Set delegation options.
    if perms.delegate_cmds != 0 {
        let val = CString::new(format!("0x{:x}", perms.delegate_cmds)).unwrap();
        fsconfig_set_string(c"delegate_cmds", &val)?;
    }
    if perms.delegate_maps != 0 {
        let val = CString::new(format!("0x{:x}", perms.delegate_maps)).unwrap();
        fsconfig_set_string(c"delegate_maps", &val)?;
    }
    if perms.delegate_progs != 0 {
        let val = CString::new(format!("0x{:x}", perms.delegate_progs)).unwrap();
        fsconfig_set_string(c"delegate_progs", &val)?;
    }
    if perms.delegate_attachs != 0 {
        let val = CString::new(format!("0x{:x}", perms.delegate_attachs)).unwrap();
        fsconfig_set_string(c"delegate_attachs", &val)?;
    }

    // Set uid/gid ownership via fsconfig (must be before CMD_CREATE).
    if let Some(uid) = perms.uid {
        let val = CString::new(format!("{uid}")).unwrap();
        fsconfig_set_string(c"uid", &val)?;
    }
    if let Some(gid) = perms.gid {
        let val = CString::new(format!("{gid}")).unwrap();
        fsconfig_set_string(c"gid", &val)?;
    }

    // fsconfig(fs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0)
    let ret = unsafe {
        libc::syscall(
            SYS_FSCONFIG,
            fs_fd.as_raw_fd(),
            FSCONFIG_CMD_CREATE,
            std::ptr::null::<libc::c_char>(),
            std::ptr::null::<libc::c_char>(),
            0,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // fsmount(fs_fd, FSMOUNT_CLOEXEC, 0)
    let mnt_fd = unsafe { libc::syscall(SYS_FSMOUNT, fs_fd.as_raw_fd(), FSMOUNT_CLOEXEC, 0u32) };
    if mnt_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mnt_fd = unsafe { OwnedFd::from_raw_fd(mnt_fd as i32) };

    // move_mount(mnt_fd, "", AT_FDCWD, path, MOVE_MOUNT_F_EMPTY_PATH)
    let ret = unsafe {
        libc::syscall(
            SYS_MOVE_MOUNT,
            mnt_fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            path_c.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
