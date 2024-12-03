use aya::{
    programs::{FEntry, KProbe},
    Btf, Ebpf,
};

#[test]
fn kprobe_args() {
    let mut bpf = Ebpf::load(crate::ARGS).unwrap();
    let kprobe_vfs_write: &mut KProbe = bpf
        .program_mut("kprobe_vfs_write")
        .unwrap()
        .try_into()
        .unwrap();
    kprobe_vfs_write.load().unwrap();
    kprobe_vfs_write.attach("vfs_write", 0).unwrap();
}

#[test]
fn fentry_args() {
    let mut bpf = Ebpf::load(crate::ARGS).unwrap();
    let fentry_vfs_write: &mut FEntry = bpf
        .program_mut("fentry_vfs_write")
        .unwrap()
        .try_into()
        .unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    fentry_vfs_write.load("vfs_write", &btf).unwrap();
    fentry_vfs_write.attach().unwrap();
}
