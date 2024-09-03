use std::{
    borrow::Cow,
    sync::{Arc, Mutex},
    time::Instant,
};

use aya::{programs::UProbe, Ebpf};
use aya_log::EbpfLogger;
use log::{Level, Log, Record};
use test_log::test;

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_ebpf_program() {
    core::hint::black_box(trigger_ebpf_program);
}

pub(crate) struct TestingLogger<F> {
    pub(crate) log: F,
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
pub(crate) struct CapturedLog<'a> {
    pub(crate) body: Cow<'a, str>,
    pub(crate) level: Level,
    pub(crate) target: Cow<'a, str>,
    pub(crate) timestamp: Option<Instant>,
}

#[test(tokio::test)]
async fn log() {
    let mut bpf = Ebpf::load(crate::LOG).unwrap();

    let captured_logs = Arc::new(Mutex::new(Vec::new()));
    {
        let captured_logs = captured_logs.clone();
        EbpfLogger::init_with_logger(
            &mut bpf,
            TestingLogger {
                log: move |record: &Record| {
                    let mut logs = captured_logs.lock().unwrap();
                    logs.push(CapturedLog {
                        body: format!("{}", record.args()).into(),
                        level: record.level(),
                        target: record.target().to_string().into(),
                        timestamp: None,
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
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let records = captured_logs.lock().unwrap();
        let len = records.len();
        if len == 0 {
            continue;
        }
        if len == logs {
            break records;
        }
        logs = len;
    };

    let mut records = records.iter();

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "Hello from eBPF!".into(),
            level: Level::Debug,
            target: "log".into(),
            timestamp: None,
        }),
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "69, 420, wao, 77616f".into(),
            level: Level::Error,
            target: "log".into(),
            timestamp: None,
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "ip structs, without format hint: ipv4: 10.0.0.1, ipv6: 2001:db8::1".into(),
            level: Level::Info,
            target: "log".into(),
            timestamp: None,
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "ip structs, with format hint: ipv4: 10.0.0.1, ipv6: 2001:db8::1".into(),
            level: Level::Info,
            target: "log".into(),
            timestamp: None,
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "ip enums, without format hint: ipv4: 10.0.0.1, ipv6: 2001:db8::1".into(),
            level: Level::Info,
            target: "log".into(),
            timestamp: None,
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "ip enums, with format hint: ipv4: 10.0.0.1, ipv6: 2001:db8::1".into(),
            level: Level::Info,
            target: "log".into(),
            timestamp: None,
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "ip as bits: ipv4: 10.0.0.1".into(),
            level: Level::Info,
            target: "log".into(),
            timestamp: None,
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "ip as octets: ipv4: 10.0.0.1, ipv6: 2001:db8::1".into(),
            level: Level::Info,
            target: "log".into(),
            timestamp: None,
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "mac lc: 04:20:06:09:00:40, mac uc: 04:20:06:09:00:40".into(),
            level: Level::Trace,
            target: "log".into(),
            timestamp: None,
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "hex lc: 2f, hex uc: 2F".into(),
            level: Level::Warn,
            target: "log".into(),
            timestamp: None,
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "hex lc: deadbeef, hex uc: DEADBEEF".into(),
            level: Level::Debug,
            target: "log".into(),
            timestamp: None,
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "42 43 44 45".into(),
            level: Level::Debug,
            target: "log".into(),
            timestamp: None,
        })
    );

    assert_eq!(records.next(), None);
}
