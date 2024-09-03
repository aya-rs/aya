use std::{
    net::UdpSocket,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use aya::{
    programs::{tc::TcAttachOptions, LinkOrder, SchedClassifier, TcAttachType},
    util::KernelVersion,
    Ebpf, EbpfLoader,
};
use aya_log::EbpfLogger;
use log::{debug, Record};
use test_log::test;

use crate::{
    tests::log::{CapturedLog, TestingLogger},
    utils::NetNsGuard,
};

fn setup_logs(loader: &mut Ebpf, logs: &Arc<Mutex<Vec<CapturedLog<'static>>>>) {
    let captured_logs = logs.clone();
    EbpfLogger::init_with_logger(
        loader,
        TestingLogger {
            log: move |record: &Record| {
                let mut logs = captured_logs.lock().unwrap();
                logs.push(CapturedLog {
                    body: format!("{}", record.args()).into(),
                    level: record.level(),
                    target: record.target().to_string().into(),
                    timestamp: Some(Instant::now()),
                });
            },
        },
    )
    .unwrap();
}

#[test(tokio::test)]
async fn tcx_ordering() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 6, 0) {
        eprintln!("skipping tcx_ordering test on kernel {kernel_version:?}");
        return;
    }

    let _netns = NetNsGuard::new();

    let mut program0 = EbpfLoader::new()
        .set_global("ORDER", &0, true)
        .load(crate::TCX)
        .unwrap();
    let mut program1 = EbpfLoader::new()
        .set_global("ORDER", &1, true)
        .load(crate::TCX)
        .unwrap();
    let mut program2 = EbpfLoader::new()
        .set_global("ORDER", &2, true)
        .load(crate::TCX)
        .unwrap();
    let mut program3 = EbpfLoader::new()
        .set_global("ORDER", &3, true)
        .load(crate::TCX)
        .unwrap();

    let logs0: Arc<Mutex<Vec<CapturedLog>>> = Arc::new(Mutex::new(Vec::new()));
    setup_logs(&mut program0, &logs0);

    let logs1 = Arc::new(Mutex::new(Vec::new()));
    setup_logs(&mut program1, &logs1);

    let logs2 = Arc::new(Mutex::new(Vec::new()));
    setup_logs(&mut program2, &logs2);

    let logs3 = Arc::new(Mutex::new(Vec::new()));
    setup_logs(&mut program3, &logs3);

    let prog0: &mut SchedClassifier = program0
        .program_mut("tcx_order")
        .unwrap()
        .try_into()
        .unwrap();
    prog0.load().unwrap();

    let prog1: &mut SchedClassifier = program1
        .program_mut("tcx_order")
        .unwrap()
        .try_into()
        .unwrap();
    prog1.load().unwrap();

    let prog2: &mut SchedClassifier = program2
        .program_mut("tcx_order")
        .unwrap()
        .try_into()
        .unwrap();
    prog2.load().unwrap();

    let prog3: &mut SchedClassifier = program3
        .program_mut("tcx_order")
        .unwrap()
        .try_into()
        .unwrap();
    prog3.load().unwrap();

    // Test LinkOrder::first() and LinkOrder::set_expected_revision()
    let mut order: LinkOrder = LinkOrder::last();
    order.set_expected_revision(u64::MAX);
    let options = TcAttachOptions::TcxOrder(order);
    let result = prog0.attach_with_options("lo", TcAttachType::Ingress, options);
    assert!(result.is_err());

    let mut order: LinkOrder = LinkOrder::last();
    order.set_expected_revision(0);
    let options = TcAttachOptions::TcxOrder(order);
    prog0
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();

    // Test LinkOrder::after_program()
    let order = LinkOrder::after_program(prog0).unwrap();
    let options = TcAttachOptions::TcxOrder(order);
    let prog1_link_id = prog1
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();

    let prog1_link = prog1.take_link(prog1_link_id).unwrap();

    // Test LinkOrder::after_link()
    let order = LinkOrder::after_link(&prog1_link).unwrap();
    let options = TcAttachOptions::TcxOrder(order);
    prog2
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();

    // Test LinkOrder::last()
    let options = TcAttachOptions::TcxOrder(LinkOrder::last());
    prog3
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();

    const PAYLOAD: &str = "hello tcx";

    let sock = UdpSocket::bind("127.0.0.1:1778").unwrap();
    let addr = sock.local_addr().unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    // We only need to send data since we're attaching tcx programs to the ingress hook
    sock.send_to(PAYLOAD.as_bytes(), addr).unwrap();

    // Allow logs to populate
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let log0 = logs0.lock().unwrap();
    let log1 = logs1.lock().unwrap();
    let log2 = logs2.lock().unwrap();
    let log3 = logs3.lock().unwrap();

    debug!("log0: {:?}", log0.first());
    debug!("log1: {:?}", log1.first());
    debug!("log2: {:?}", log2.first());
    debug!("log3: {:?}", log3.first());

    // sort logs by timestamp
    let mut sorted_logs = [
        log0.first().unwrap(),
        log1.first().unwrap(),
        log2.first().unwrap(),
        log3.first().unwrap(),
    ];
    sorted_logs.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    assert!(sorted_logs[0].body.contains("order: 0"));
    assert!(sorted_logs[1].body.contains("order: 1"));
    assert!(sorted_logs[2].body.contains("order: 2"));
    assert!(sorted_logs[3].body.contains("order: 3"));
}
