//! BPF token tests.
//!
//! The kernel only creates a BPF token in the non-initial user namespace that
//! owns the bpffs instance, and only a privileged process may set the
//! delegation options of a bpffs instance. Like the kernel selftests, the
//! tests below therefore fork a child that enters new user and mount
//! namespaces and creates a bpffs context with `fsopen(2)`. The privileged
//! parent configures and mounts that context and hands the mount back to the
//! child, which then creates the token.
//!
//! See <https://github.com/torvalds/linux/blob/v6.9/tools/testing/selftests/bpf/prog_tests/token.c>.

use std::{
    fs,
    io::{IoSlice, IoSliceMut},
    os::{
        fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd},
        unix::ffi::OsStrExt as _,
    },
    panic::{self, AssertUnwindSafe},
};

use aya::{
    maps::MapType,
    programs::{CgroupSkbAttachType, ProgramType},
    sys::SyscallError,
    token::{BpfCommand, BpfToken, BpffsDelegation, create_bpffs_context, mount_delegated_bpffs},
    util::KernelVersion,
};
use nix::{
    errno::Errno,
    fcntl::{OFlag, openat},
    mount::{MntFlags, umount2},
    sched::{CloneFlags, unshare},
    sys::{
        socket::{
            AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
            recvmsg, sendmsg, socketpair,
        },
        stat::Mode,
        wait::{WaitStatus, waitpid},
    },
    unistd::{ForkResult, fork},
};

fn kernel_supports_bpf_token() -> bool {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 9, 0) {
        eprintln!(
            "skipping test on kernel {kernel_version:?}, BPF token was added in 6.9.0; see https://github.com/torvalds/linux/commit/35f96de04127"
        );
        return false;
    }
    true
}

/// Opens the root directory of a detached bpffs mount.
///
/// `fsmount(2)` returns an `O_PATH` file descriptor, which `BPF_TOKEN_CREATE` rejects.
fn open_root(mount: OwnedFd) -> Result<OwnedFd, Errno> {
    openat(
        mount,
        c".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
}

fn send_fd(sock: BorrowedFd<'_>, fd: BorrowedFd<'_>) -> Result<(), Errno> {
    let fds = [fd.as_raw_fd()];
    sendmsg::<()>(
        sock.as_raw_fd(),
        &[IoSlice::new(&[0])],
        &[ControlMessage::ScmRights(&fds)],
        MsgFlags::empty(),
        None,
    )
    .map(drop)
}

fn recv_fd(sock: BorrowedFd<'_>) -> Result<OwnedFd, Errno> {
    let mut buf = [0];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg_buf = nix::cmsg_space!(RawFd);
    let msg = recvmsg::<()>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )?;
    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg
            && let [fd] = fds.as_slice()
        {
            // SAFETY: the kernel installed a new file descriptor for us.
            return Ok(unsafe { OwnedFd::from_raw_fd(*fd) });
        }
    }
    Err(Errno::EBADMSG)
}

fn enter_userns() -> Result<(), Errno> {
    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)?;
    // Map the root user, like the kernel selftests do.
    let write = |path: &str, contents: &str| {
        fs::write(path, contents).map_err(|err| Errno::from_raw(err.raw_os_error().unwrap_or(0)))
    };
    write("/proc/self/uid_map", "0 0 1")?;
    write("/proc/self/setgroups", "deny")?;
    write("/proc/self/gid_map", "0 0 1")?;
    Ok(())
}

fn child_main(sock: BorrowedFd<'_>, f: fn(OwnedFd) -> Result<(), Errno>) -> Result<(), Errno> {
    enter_userns()?;
    let fs_fd = create_bpffs_context().map_err(|err| errno(&err))?;
    send_fd(sock, fs_fd.as_fd())?;
    let bpffs = open_root(recv_fd(sock)?)?;
    // 0 encodes success, so encode `Errno::UnknownErrno` (0) as -1.
    let result: i32 = match f(bpffs) {
        Ok(()) => 0,
        Err(errno) => match errno as i32 {
            0 => -1,
            errno => errno,
        },
    };
    nix::unistd::write(sock, &result.to_ne_bytes()).map(drop)
}

/// Runs `f` in a child process inside a new user namespace that owns a bpffs
/// instance mounted with `delegation`.
///
/// `f` receives a file descriptor for the root directory of that instance.
fn with_userns_bpffs(
    delegation: &BpffsDelegation,
    f: fn(OwnedFd) -> Result<(), Errno>,
) -> Result<(), Errno> {
    let (parent_sock, child_sock) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .unwrap();

    // SAFETY: the child only performs syscalls and allocations before it exits; glibc keeps
    // malloc usable after fork, and the test harness runs a single test thread.
    match unsafe { fork() }.unwrap() {
        ForkResult::Child => {
            drop(parent_sock);
            // Don't let a panic unwind into the test harness running in the child.
            let result =
                panic::catch_unwind(AssertUnwindSafe(|| child_main(child_sock.as_fd(), f)));
            let code = match result {
                Ok(Ok(())) => 0,
                Ok(Err(_)) | Err(_) => 1,
            };
            // SAFETY: exit without running the test harness' atexit handlers.
            unsafe { libc::_exit(code) }
        }
        ForkResult::Parent { child } => {
            drop(child_sock);
            let fs_fd = recv_fd(parent_sock.as_fd()).unwrap();
            let mount = mount_delegated_bpffs(fs_fd, delegation).unwrap();
            send_fd(parent_sock.as_fd(), mount.as_fd()).unwrap();

            let mut result = [0; size_of::<i32>()];
            let read = nix::unistd::read(parent_sock.as_fd(), &mut result).unwrap();
            assert_eq!(waitpid(child, None).unwrap(), WaitStatus::Exited(child, 0));
            assert_eq!(read, result.len());
            match i32::from_ne_bytes(result) {
                0 => Ok(()),
                errno => Err(Errno::from_raw(errno)),
            }
        }
    }
}

fn errno(err: &SyscallError) -> Errno {
    let SyscallError { call: _, io_error } = err;
    Errno::from_raw(io_error.raw_os_error().unwrap())
}

fn create_token(bpffs: OwnedFd) -> Result<(), Errno> {
    BpfToken::create(bpffs).map(drop).map_err(|err| errno(&err))
}

#[test_log::test]
fn create() {
    if !kernel_supports_bpf_token() {
        return;
    }
    assert_eq!(
        with_userns_bpffs(BpffsDelegation::default().all_commands(), create_token),
        Ok(())
    );
}

#[test_log::test]
fn create_without_delegation() {
    if !kernel_supports_bpf_token() {
        return;
    }
    // https://github.com/torvalds/linux/blob/v6.9/kernel/bpf/token.c#L165-L172
    assert_eq!(
        with_userns_bpffs(&BpffsDelegation::default(), create_token),
        Err(Errno::ENOENT)
    );
}

#[test_log::test]
fn create_in_init_user_ns() {
    if !kernel_supports_bpf_token() {
        return;
    }
    let fs_fd = create_bpffs_context().unwrap();
    let mount = mount_delegated_bpffs(fs_fd, BpffsDelegation::default().all_commands()).unwrap();
    let bpffs = open_root(mount).unwrap();
    // https://github.com/torvalds/linux/blob/v6.9/kernel/bpf/token.c#L159-L163
    assert_eq!(create_token(bpffs), Err(Errno::EOPNOTSUPP));
}

/// Attaches a detached bpffs mount and returns its super block options.
fn bpffs_options(mount: BorrowedFd<'_>) -> String {
    // https://github.com/torvalds/linux/blob/v6.9/include/uapi/linux/mount.h#L72
    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;

    let dir = tempfile::tempdir().unwrap();
    let path = std::ffi::CString::new(dir.path().as_os_str().as_bytes()).unwrap();
    let ret = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mount.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            path.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    Errno::result(ret).unwrap();
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap();
    // The caller still holds the mount file descriptor.
    umount2(dir.path(), MntFlags::MNT_DETACH).unwrap();

    // https://docs.kernel.org/filesystems/proc.html#proc-pid-mountinfo-information-about-mounts
    let mount_point = dir.path().to_str().unwrap();
    let line = mountinfo
        .lines()
        .find(|line| line.split(' ').nth(4) == Some(mount_point))
        .unwrap();
    line.rsplit(' ').next().unwrap().to_owned()
}

#[test_log::test]
fn delegation_options() {
    if !kernel_supports_bpf_token() {
        return;
    }
    let mut delegation = BpffsDelegation::default();
    delegation
        .command(BpfCommand::BPF_MAP_CREATE)
        .command(BpfCommand::BPF_PROG_LOAD)
        .map_type(MapType::Array)
        .program_type(ProgramType::SocketFilter)
        .attach_type(CgroupSkbAttachType::Ingress);
    let mount = mount_delegated_bpffs(create_bpffs_context().unwrap(), &delegation).unwrap();
    let options = bpffs_options(mount.as_fd());
    for expected in [
        "delegate_cmds=map_create:prog_load",
        "delegate_maps=array",
        "delegate_progs=socket_filter",
        "delegate_attachs=cgroup_inet_ingress",
    ] {
        assert!(
            options.split(',').any(|option| option == expected),
            "{expected} not in {options}"
        );
    }

    let mut delegation = BpffsDelegation::default();
    delegation
        .all_commands()
        .all_map_types()
        .all_program_types()
        .all_attach_types();
    let mount = mount_delegated_bpffs(create_bpffs_context().unwrap(), &delegation).unwrap();
    let options = bpffs_options(mount.as_fd());
    for expected in [
        "delegate_cmds=any",
        "delegate_maps=any",
        "delegate_progs=any",
        "delegate_attachs=any",
    ] {
        assert!(
            options.split(',').any(|option| option == expected),
            "{expected} not in {options}"
        );
    }
}
