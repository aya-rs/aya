use aya::{programs::SocketFilter, Ebpf};

#[test]
fn socket_filter_load() {
    let mut bpf = Ebpf::load(crate::SOCKET_FILTER).unwrap();
    let prog: &mut SocketFilter = bpf
        .program_mut("read_one")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

}