use std::{
    io,
    os::fd::{AsFd as _, AsRawFd as _, RawFd},
};

use aya_obj::{ExternModuleBtfProvider, ExternResolverModule, btf::Btf};
use libc::E2BIG;
use log::{debug, warn};
use object::Endianness;

use crate::{
    EbpfError, MockableFd,
    programs::ProgramError,
    sys::{bpf_btf_get_fd_by_id, bpf_btf_get_info_by_fd, iter_btf_ids},
};

#[derive(Debug)]
pub(crate) struct KernelModuleBtfSet {
    modules: Vec<LoadedModuleBtf>,
}

#[derive(Debug)]
pub(crate) struct LoadedModuleBtf {
    btf: Btf,
    fd: MockableFd,
}

impl ExternModuleBtfProvider for KernelModuleBtfSet {
    type Error = EbpfError;

    fn extern_resolution_modules(&self) -> Result<Vec<ExternResolverModule<'_>>, Self::Error> {
        self.modules()
            .enumerate()
            .map(|(i, module)| {
                let fd_idx =
                    i16::try_from(i + 1).map_err(|_err| EbpfError::TooManyModuleBtfObjects {
                        count: self.modules.len(),
                    })? as u16;

                Ok(ExternResolverModule {
                    btf: module.btf(),
                    fd_idx,
                    btf_obj_fd: module.raw_fd(),
                })
            })
            .collect()
    }
}

impl KernelModuleBtfSet {
    pub(crate) fn discover() -> Result<Self, EbpfError> {
        let mut modules = Vec::new();

        for id in iter_btf_ids() {
            let id = match id {
                Ok(id) => id,
                Err(err) if err.io_error.kind() == io::ErrorKind::PermissionDenied => {
                    debug!("stopping module BTF loading, missing privileges");
                    return Ok(Self { modules });
                }
                Err(err) => return Err(ProgramError::SyscallError(err).into()),
            };

            let fd = match bpf_btf_get_fd_by_id(id) {
                Ok(fd) => fd,
                Err(err) if err.io_error.kind() == io::ErrorKind::NotFound => continue,
                Err(err) if err.io_error.kind() == io::ErrorKind::PermissionDenied => {
                    debug!("stopping module BTF loading, missing privileges");
                    return Ok(Self { modules });
                }
                Err(err) => return Err(ProgramError::SyscallError(err).into()),
            };

            let mut name_buf = [0u8; 64];
            let info = match bpf_btf_get_info_by_fd(fd.as_fd(), |info| {
                info.name = name_buf.as_mut_ptr() as u64;
                info.name_len = name_buf.len() as u32;
            }) {
                Ok(info) => info,
                Err(err) if err.io_error.kind() == io::ErrorKind::PermissionDenied => {
                    debug!("stopping module BTF loading, missing privileges");
                    return Ok(Self { modules });
                }
                Err(err) if err.io_error.raw_os_error() == Some(E2BIG) => {
                    debug!("stopping module BTF loading, unsupported BTF info layout");
                    return Ok(Self { modules });
                }
                Err(err) => return Err(EbpfError::from(ProgramError::SyscallError(err))),
            };

            if info.kernel_btf == 0 {
                continue;
            }

            let name = name_from_buf(&name_buf, info.name_len);
            if name.is_empty() || name == "vmlinux" {
                continue;
            }

            let mut btf_buf = vec![0u8; info.btf_size as usize];
            match bpf_btf_get_info_by_fd(fd.as_fd(), |info| {
                info.btf = btf_buf.as_mut_ptr() as u64;
                info.btf_size = btf_buf.len() as u32;
            }) {
                Ok(_info) => {}
                Err(err) if err.io_error.kind() == io::ErrorKind::PermissionDenied => {
                    debug!("stopping module BTF loading, missing privileges");
                    return Ok(Self { modules });
                }
                Err(err) => return Err(EbpfError::from(ProgramError::SyscallError(err))),
            }

            let btf = match Btf::parse(&btf_buf, native_endianness()) {
                Ok(btf) => btf,
                Err(err) => {
                    warn!("skipping module BTF {name}: {err}");
                    continue;
                }
            };

            modules.push(LoadedModuleBtf { btf, fd });
        }

        Ok(Self { modules })
    }

    pub(crate) fn modules(&self) -> impl Iterator<Item = &LoadedModuleBtf> {
        self.modules.iter()
    }

    pub(crate) fn fd_array(&self) -> Vec<RawFd> {
        let mut fds = Vec::with_capacity(self.modules.len() + 1);
        fds.push(-1);
        fds.extend(self.modules().map(LoadedModuleBtf::raw_fd));
        fds
    }
}

impl LoadedModuleBtf {
    pub(crate) const fn btf(&self) -> &Btf {
        &self.btf
    }

    pub(crate) fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

const fn native_endianness() -> Endianness {
    if cfg!(target_endian = "big") {
        Endianness::Big
    } else {
        Endianness::Little
    }
}

fn name_from_buf(buf: &[u8], name_len: u32) -> String {
    let len = usize::min(name_len as usize, buf.len());
    let bytes = &buf[..len];
    let len = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}
#[cfg(test)]
mod tests {
    use std::os::fd::FromRawFd as _;

    use super::*;

    fn fake_module(raw_fd: RawFd) -> LoadedModuleBtf {
        LoadedModuleBtf {
            btf: Btf::new(),
            fd: unsafe { MockableFd::from_raw_fd(raw_fd) },
        }
    }

    #[test]
    fn fd_array_indices_match_extern_resolution_modules() {
        let modules = KernelModuleBtfSet {
            modules: vec![
                fake_module(MockableFd::mock_signed_fd()),
                fake_module(MockableFd::mock_signed_fd() + 1),
            ],
        };

        let resolver_modules = modules.extern_resolution_modules().unwrap();
        let fd_array = modules.fd_array();

        assert_eq!(fd_array[0], -1);
        assert_eq!(resolver_modules[0].fd_idx, 1);
        assert_eq!(
            fd_array[resolver_modules[0].fd_idx as usize],
            resolver_modules[0].btf_obj_fd
        );

        assert_eq!(resolver_modules[1].fd_idx, 2);
        assert_eq!(
            fd_array[resolver_modules[1].fd_idx as usize],
            resolver_modules[1].btf_obj_fd
        );
    }
}
