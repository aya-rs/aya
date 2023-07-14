use std::sync::{Arc, Mutex};

use assert_matches::assert_matches;
use aya::{programs::UProbe, Bpf};
use aya_log::BpfLogger;
use log::{Level, Log, Record};

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_ebpf_program() {}

struct TestingLogger<F> {
    log: F,
}

impl<F: Send + Sync + Fn(&Record)> Log for TestingLogger<F> {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn flush(&self) {}

    fn log(&self, record: &Record) {
        let Self { log } = self;
        log(record);
    }
}

#[derive(Debug, PartialEq)]
struct CapturedLog {
    pub body: String,
    pub level: Level,
    pub target: String,
}

#[tokio::test]
async fn log() {
    let mut bpf = Bpf::load(crate::LOG).unwrap();

    let captured_logs = Arc::new(Mutex::new(Vec::new()));
    {
        let captured_logs = captured_logs.clone();
        BpfLogger::init_with_logger(
            &mut bpf,
            TestingLogger {
                log: move |record: &Record| {
                    let mut logs = captured_logs.lock().unwrap();
                    logs.push(CapturedLog {
                        body: format!("{}", record.args()),
                        level: record.level(),
                        target: record.target().to_string(),
                    });
                },
            },
        )
        .unwrap();
    }

    let prog: &mut UProbe = bpf.program_mut("test_log").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach(Some("trigger_ebpf_program"), 0, "/proc/self/exe", None)
        .unwrap();

    // Call the function that the uprobe is attached to, so it starts logging.
    trigger_ebpf_program();

    let mut logs = 0;
    let records = loop {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let records = captured_logs.lock().unwrap();
        if records.len() == logs {
            break records;
        }
        logs = records.len();
    };

    let mut records = records.iter();

    assert_matches!(
        records.next(),
        Some(CapturedLog {
            body,
            level: Level::Debug,
            target,
         }) if body == "Hello from eBPF!" && target == "log"
    );

    assert_matches!(
        records.next(),
        Some(CapturedLog {
            body,
            level: Level::Error,
            target,
        }) if body == "69, 420, wao" && target == "log"
    );

    assert_matches!(
        records.next(),
        Some(CapturedLog {
            body,
            level: Level::Info,
            target,
        }) if body == "ipv4: 10.0.0.1, ipv6: 2001:db8::1" && target == "log"
    );

    assert_matches!(
        records.next(),
        Some(CapturedLog {
            body,
            level: Level::Trace,
            target,
        }) if body == "mac lc: 04:20:06:09:00:40, mac uc: 04:20:06:09:00:40" && target == "log"
    );

    assert_matches!(
        records.next(),
        Some(CapturedLog {
            body,
            level: Level::Warn,
            target,
        }) if body == "hex lc: 2f, hex uc: 2F" && target == "log"
    );

    assert_matches!(
        records.next(),
        Some(CapturedLog {
            body,
            level: Level::Debug,
            target,
        }) if body == "hex lc: deadbeef, hex uc: DEADBEEF" && target == "log"
    );

    assert_eq!(records.next(), None);
}
