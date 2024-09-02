use std::{
    error::Error,
    fs::OpenOptions,
    os::{fd::IntoRawFd, unix::fs::OpenOptionsExt},
};

use aya::{programs::Lsm, Ebpf};
use aya_obj::btf::Btf;
use libc::{linkat, AT_EMPTY_PATH, AT_FDCWD, O_TMPFILE};

use crate::INODE_STORAGE_TEST;

#[test]
fn no_link_to_tmp() -> Result<(), Box<dyn Error>> {
    let mut bpf = Ebpf::load(INODE_STORAGE_TEST)?;
    let btf = Btf::from_sys_fs()?;

    let rename: &mut Lsm = bpf
        .program_mut("inode_post_create_tmpfile")
        .unwrap()
        .try_into()?;
    rename.load("inode_post_create_tmpfile", &btf)?;
    rename.attach()?;

    let link: &mut Lsm = bpf.program_mut("inode_link").unwrap().try_into()?;
    link.load("inode_link", &btf)?;
    link.attach()?;

    // create a temporary file
    let tmpfile = OpenOptions::new()
        .custom_flags(O_TMPFILE)
        .create_new(true)
        .open("/tmp/")?;

    let fd = tmpfile.into_raw_fd();
    let res = unsafe {
        linkat(
            fd,
            c"".as_ptr(),
            AT_FDCWD,
            c"/tmp/blah".as_ptr(),
            AT_EMPTY_PATH,
        )
    };

    assert_eq!(130, res);

    Ok(())
}
