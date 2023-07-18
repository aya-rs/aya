//! Extension programs.
use std::os::fd::{AsRawFd, RawFd};
use thiserror::Error;

use object::Endianness;

use crate::{
    generated::{bpf_attach_type::BPF_CGROUP_INET_INGRESS, bpf_prog_type::BPF_PROG_TYPE_EXT},
    obj::btf::BtfKind,
    programs::{
        define_link_wrapper, load_program, FdLink, FdLinkId, ProgramData, ProgramError, ProgramFd,
    },
    sys::{self, bpf_link_create},
    Btf,
};

/// The type returned when loading or attaching an [`Extension`] fails.
#[derive(Debug, Error)]
pub enum ExtensionError {
    /// Target BPF program does not have BTF loaded to the kernel.
    #[error("target BPF program does not have BTF loaded to the kernel")]
    NoBTF,
}

/// A program used to extend existing BPF programs.
///
/// [`Extension`] programs can be loaded to replace a global
/// function in a program that has already been loaded.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.9
///
/// # Examples
///
/// ```no_run
/// use aya::{BpfLoader, programs::{Xdp, XdpFlags, Extension}};
///
/// let mut bpf = BpfLoader::new().extension("extension").load_file("app.o")?;
/// let prog: &mut Xdp = bpf.program_mut("main").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach("eth0", XdpFlags::default())?;
///
/// let prog_fd = prog.fd().unwrap();
/// let ext: &mut Extension = bpf.program_mut("extension").unwrap().try_into()?;
/// ext.load(prog_fd, "function_to_replace")?;
/// ext.attach()?;
/// Ok::<(), aya::BpfError>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_EXT")]
pub struct Extension {
    pub(crate) data: ProgramData<ExtensionLink>,
}

impl Extension {
    /// Loads the extension inside the kernel.
    ///
    /// Prepares the code included in the extension to replace the code of the function
    /// `func_name` within the eBPF program represented by the `program` file descriptor.
    /// This requires that both the [`Extension`] and `program` have had their BTF
    /// loaded into the kernel.
    ///
    /// The BPF verifier requires that we specify the target program and function name
    /// at load time, so it can identify that the program and target are BTF compatible
    /// and to enforce this constraint when programs are attached.
    ///
    /// The extension code will be loaded but inactive until it's attached.
    /// There are no restrictions on what functions may be replaced, so you could replace
    /// the main entry point of your program with an extension.
    pub fn load(&mut self, program: ProgramFd, func_name: &str) -> Result<(), ProgramError> {
        let target_prog_fd = program.as_raw_fd();
        let (btf_fd, btf_id) = get_btf_info(target_prog_fd, func_name)?;

        self.data.attach_btf_obj_fd = Some(btf_fd as u32);
        self.data.attach_prog_fd = Some(target_prog_fd);
        self.data.attach_btf_id = Some(btf_id);
        load_program(BPF_PROG_TYPE_EXT, &mut self.data)
    }

    /// Attaches the extension.
    ///
    /// Attaches the extension to the program and function name specified at load time,
    /// effectively replacing the original target function.
    ///
    /// The returned value can be used to detach the extension and restore the
    /// original function, see [Extension::detach].
    pub fn attach(&mut self) -> Result<ExtensionLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let target_fd = self.data.attach_prog_fd.ok_or(ProgramError::NotLoaded)?;
        let btf_id = self.data.attach_btf_id.ok_or(ProgramError::NotLoaded)?;
        // the attach type must be set as 0, which is bpf_attach_type::BPF_CGROUP_INET_INGRESS
        let link_fd = bpf_link_create(prog_fd, target_fd, BPF_CGROUP_INET_INGRESS, Some(btf_id), 0)
            .map_err(|(_, io_error)| ProgramError::SyscallError {
                call: "bpf_link_create",
                io_error,
            })? as RawFd;
        self.data
            .links
            .insert(ExtensionLink::new(FdLink::new(link_fd)))
    }

    /// Attaches the extension to another program.
    ///
    /// Attaches the extension to a program and/or function other than the one provided
    /// at load time. You may only attach to another program/function if the BTF
    /// type signature is identical to that which was verified on load. Attempting to
    /// attach to an invalid program/function will result in an error.
    ///
    /// Once attached, the extension effectively replaces the original target function.
    ///
    /// The returned value can be used to detach the extension and restore the
    /// original function, see [Extension::detach].
    pub fn attach_to_program(
        &mut self,
        program: ProgramFd,
        func_name: &str,
    ) -> Result<ExtensionLinkId, ProgramError> {
        let target_fd = program.as_raw_fd();
        let (_, btf_id) = get_btf_info(target_fd, func_name)?;
        let prog_fd = self.data.fd_or_err()?;
        // the attach type must be set as 0, which is bpf_attach_type::BPF_CGROUP_INET_INGRESS
        let link_fd = bpf_link_create(prog_fd, target_fd, BPF_CGROUP_INET_INGRESS, Some(btf_id), 0)
            .map_err(|(_, io_error)| ProgramError::SyscallError {
                call: "bpf_link_create",
                io_error,
            })? as RawFd;
        self.data
            .links
            .insert(ExtensionLink::new(FdLink::new(link_fd)))
    }

    /// Detaches the extension.
    ///
    /// Detaching restores the original code overridden by the extension program.
    /// See [Extension::attach].
    pub fn detach(&mut self, link_id: ExtensionLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: ExtensionLinkId) -> Result<ExtensionLink, ProgramError> {
        self.data.take_link(link_id)
    }
}

/// Retrieves the FD of the BTF object for the provided `prog_fd` and the BTF ID of the function
/// with the name `func_name` within that BTF object.
fn get_btf_info(prog_fd: i32, func_name: &str) -> Result<(RawFd, u32), ProgramError> {
    // retrieve program information
    let info =
        sys::bpf_prog_get_info_by_fd(prog_fd).map_err(|io_error| ProgramError::SyscallError {
            call: "bpf_prog_get_info_by_fd",
            io_error,
        })?;

    // btf_id refers to the ID of the program btf that was loaded with bpf(BPF_BTF_LOAD)
    if info.btf_id == 0 {
        return Err(ProgramError::ExtensionError(ExtensionError::NoBTF));
    }

    // the bpf fd of the BTF object
    let btf_fd =
        sys::bpf_btf_get_fd_by_id(info.btf_id).map_err(|io_error| ProgramError::SyscallError {
            call: "bpf_btf_get_fd_by_id",
            io_error,
        })?;

    // we need to read the btf bytes into a buffer but we don't know the size ahead of time.
    // assume 4kb. if this is too small we can resize based on the size obtained in the response.
    let mut buf = vec![0u8; 4096];
    let btf_info = match sys::btf_obj_get_info_by_fd(btf_fd, &buf) {
        Ok(info) => {
            if info.btf_size > buf.len() as u32 {
                buf.resize(info.btf_size as usize, 0u8);
                let btf_info = sys::btf_obj_get_info_by_fd(btf_fd, &buf).map_err(|io_error| {
                    ProgramError::SyscallError {
                        call: "bpf_prog_get_info_by_fd",
                        io_error,
                    }
                })?;
                Ok(btf_info)
            } else {
                Ok(info)
            }
        }
        Err(io_error) => Err(ProgramError::SyscallError {
            call: "bpf_prog_get_info_by_fd",
            io_error,
        }),
    }?;

    let btf = Btf::parse(&buf[0..btf_info.btf_size as usize], Endianness::default())
        .map_err(ProgramError::Btf)?;

    let btf_id = btf
        .id_by_type_name_kind(func_name, BtfKind::Func)
        .map_err(ProgramError::Btf)?;

    Ok((btf_fd, btf_id))
}

define_link_wrapper!(
    /// The link used by [Extension] programs.
    ExtensionLink,
    /// The type returned by [Extension::attach]. Can be passed to [Extension::detach].
    ExtensionLinkId,
    FdLink,
    FdLinkId
);
