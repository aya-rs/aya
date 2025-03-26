use std::io::BufRead as _;

use aya::{Btf, Ebpf, programs::Iter};

#[cfg_attr(aya_integration_test, test_log::test)]
#[cfg_attr(not(aya_integration_test), allow(dead_code))]
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
    let expected_values = ["1        1        init", "1        1        systemd"];
    assert!(
        expected_values.contains(&line_init.as_str()),
        "Unexpected line_init value: '{}', expected one of: {:?}",
        line_init,
        expected_values
    );
}
