use aya::{
    include_bytes_aligned,
    programs::{FEntry, KProbe},
    Bpf, Btf,
};

use super::{integration_test, IntegrationTest};

#[integration_test]
fn kprobe_args() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/args");
    let mut bpf = Bpf::load(bytes).unwrap();
    let kprobe_vfs_write: &mut KProbe = bpf
        .program_mut("kprobe_vfs_write")
        .unwrap()
        .try_into()
        .unwrap();
    kprobe_vfs_write.load().unwrap();
    kprobe_vfs_write.attach("vfs_write", 0).unwrap();
}

#[integration_test]
fn fentry_args() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/args");
    let mut bpf = Bpf::load(bytes).unwrap();
    let fentry_vfs_write: &mut FEntry = bpf
        .program_mut("fentry_vfs_write")
        .unwrap()
        .try_into()
        .unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    fentry_vfs_write.load("vfs_write", &btf).unwrap();
    fentry_vfs_write.attach().unwrap();
}
