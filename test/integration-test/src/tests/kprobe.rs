use std::{sync::mpsc::sync_channel, thread};

use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, MapData},
    programs::{KProbe, links::Link as _},
};

#[test_log::test]
fn tracefs_cleanup() {
    let mut bpf = Ebpf::load(crate::TEST).unwrap();
    let program: &mut KProbe = bpf.program_mut("test_kprobe").unwrap().try_into().unwrap();
    program.load().unwrap();
    super::check_tracefs_cleanup(
        "kprobe",
        1,
        || {
            let id = program.attach("try_to_wake_up", 0).unwrap();
            program.take_link(id).unwrap()
        },
        |link| link.detach().unwrap(),
    );
}

#[test_log::test]
fn kprobe_triggers() {
    let target_tgid = std::process::id();
    let mut bpf = EbpfLoader::new()
        .override_global("TARGET_TGID", &target_tgid, true)
        .load(crate::KPROBE)
        .unwrap();

    let hits = Array::try_from(bpf.take_map("HITS").unwrap()).unwrap();

    let prog: &mut KProbe = bpf
        .program_mut("test_kprobe_trigger")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("try_to_wake_up", 0).unwrap();

    let hits_before = read_hits(&hits);

    let (tx, rx) = sync_channel::<()>(0);
    let worker = thread::spawn(move || {
        rx.recv().unwrap();
    });

    tx.send(()).unwrap();

    worker.join().unwrap();

    let hits_after = read_hits(&hits);
    assert!(
        hits_after > hits_before,
        "expected kprobe hits to increase, before={hits_before}, after={hits_after}"
    );
}

fn read_hits(hits: &Array<MapData, u64>) -> u64 {
    hits.get(&0, 0).unwrap()
}
