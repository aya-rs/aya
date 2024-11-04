use std::io::BufRead;

use aya::{programs::Iter, Btf, Ebpf};
use test_log::test;
use tokio::io::AsyncBufReadExt;

#[test]
fn iter_task() {
    let mut ebpf = Ebpf::load(crate::ITER_TASK).unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    let prog: &mut Iter = ebpf.program_mut("iter_task").unwrap().try_into().unwrap();
    prog.load("task", &btf).unwrap();

    let link_id = prog.attach().unwrap();
    let link = prog.take_link(link_id).unwrap();
    let file = link.into_file().unwrap();
    let reader = std::io::BufReader::new(file);

    let mut lines = reader.lines();
    let line_title = lines.next().unwrap().unwrap();
    let line_init = lines.next().unwrap().unwrap();

    assert_eq!(line_title, "tgid     pid      name");
    assert!(line_init == "1        1        init" || line_init == "1        1        systemd");
}

#[test(tokio::test)]
async fn iter_async_task() {
    let mut ebpf = Ebpf::load(crate::ITER_TASK).unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    let prog: &mut Iter = ebpf.program_mut("iter_task").unwrap().try_into().unwrap();
    prog.load("task", &btf).unwrap();

    let link_id = prog.attach().unwrap();
    let link = prog.take_link(link_id).unwrap();
    let file = link.into_tokio_file().unwrap();
    let reader = tokio::io::BufReader::new(file);

    let mut lines = reader.lines();
    let line_title = lines.next_line().await.unwrap().unwrap();
    let line_init = lines.next_line().await.unwrap().unwrap();

    assert_eq!(line_title, "tgid     pid      name");
    assert!(line_init == "1        1        init" || line_init == "1        1        systemd");
}
