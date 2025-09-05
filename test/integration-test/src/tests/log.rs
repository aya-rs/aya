use std::{borrow::Cow, sync::Mutex};

use aya::{Ebpf, EbpfLoader, programs::UProbe};
use aya_log::EbpfLogger;
use log::{Level, Log, Record};

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_ebpf_program() {
    core::hint::black_box(trigger_ebpf_program);
}

struct TestingLogger<F> {
    log: Mutex<F>,
}

impl<F: Send + FnMut(&Record)> Log for TestingLogger<F> {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn flush(&self) {}

    fn log(&self, record: &Record) {
        let Self { log } = self;
        let mut log = log.lock().unwrap();
        log(record);
    }
}

#[derive(Debug, PartialEq)]
struct CapturedLog<'a> {
    pub body: Cow<'a, str>,
    pub level: Level,
    pub target: Cow<'a, str>,
}

#[test_log::test]
fn log() {
    let mut bpf = Ebpf::load(crate::LOG).unwrap();

    let mut captured_logs = Vec::new();
    let logger = TestingLogger {
        log: Mutex::new(|record: &Record| {
            captured_logs.push(CapturedLog {
                body: format!("{}", record.args()).into(),
                level: record.level(),
                target: record.target().to_string().into(),
            });
        }),
    };
    let mut logger = EbpfLogger::init_with_logger(&mut bpf, &logger).unwrap();

    let prog: &mut UProbe = bpf.program_mut("test_log").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("trigger_ebpf_program", "/proc/self/exe", None, None)
        .unwrap();

    // Call the function that the uprobe is attached to, so it starts logging.
    trigger_ebpf_program();

    logger.flush();

    let mut records = captured_logs.iter();

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "Hello from eBPF!".into(),
            level: Level::Debug,
            target: "log".into(),
        }),
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "69, 420, wao, 77616f".into(),
            level: Level::Error,
            target: "log".into(),
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "ip structs, without format hint: ipv4: 10.0.0.1, ipv6: 2001:db8::1".into(),
            level: Level::Info,
            target: "log".into(),
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "ip structs, with format hint: ipv4: 10.0.0.1, ipv6: 2001:db8::1".into(),
            level: Level::Info,
            target: "log".into(),
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "ip enums, without format hint: ipv4: 10.0.0.1, ipv6: 2001:db8::1".into(),
            level: Level::Info,
            target: "log".into(),
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "ip enums, with format hint: ipv4: 10.0.0.1, ipv6: 2001:db8::1".into(),
            level: Level::Info,
            target: "log".into(),
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "ip as bits: ipv4: 10.0.0.1".into(),
            level: Level::Info,
            target: "log".into(),
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "ip as octets: ipv4: 10.0.0.1, ipv6: 2001:db8::1".into(),
            level: Level::Info,
            target: "log".into(),
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "mac lc: 04:20:06:09:00:40, mac uc: 04:20:06:09:00:40".into(),
            level: Level::Trace,
            target: "log".into(),
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "hex lc: 2f, hex uc: 2F".into(),
            level: Level::Warn,
            target: "log".into(),
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "hex lc: deadbeef, hex uc: DEADBEEF".into(),
            level: Level::Debug,
            target: "log".into(),
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "42 43 44 45".into(),
            level: Level::Debug,
            target: "log".into(),
        })
    );

    assert_eq!(records.next(), None);
}

#[test_log::test]
fn log_level_only_error_warn() {
    let level = aya_log::Level::Warn as u8;
    let mut bpf = EbpfLoader::new()
        .set_global(aya_log::LEVEL, &level, true /* must_exist */)
        .load(crate::LOG)
        .unwrap();

    let mut captured_logs = Vec::new();
    let logger = TestingLogger {
        log: Mutex::new(|record: &Record| {
            captured_logs.push(CapturedLog {
                body: format!("{}", record.args()).into(),
                level: record.level(),
                target: record.target().to_string().into(),
            });
        }),
    };
    let mut logger = EbpfLogger::init_with_logger(&mut bpf, &logger).unwrap();

    let prog: &mut UProbe = bpf.program_mut("test_log").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("trigger_ebpf_program", "/proc/self/exe", None, None)
        .unwrap();

    trigger_ebpf_program();
    logger.flush();

    let mut records = captured_logs.iter();

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "69, 420, wao, 77616f".into(),
            level: Level::Error,
            target: "log".into(),
        })
    );

    assert_eq!(
        records.next(),
        Some(&CapturedLog {
            body: "hex lc: 2f, hex uc: 2F".into(),
            level: Level::Warn,
            target: "log".into(),
        })
    );

    assert_eq!(records.next(), None);
}

#[test_log::test]
fn log_level_prevents_verif_fail() {
    let level = aya_log::Level::Warn as u8;
    let mut bpf = EbpfLoader::new()
        .set_global(aya_log::LEVEL, &level, true /* must_exist */)
        .load(crate::LOG)
        .unwrap();

    let mut captured_logs = Vec::new();
    let logger = TestingLogger {
        log: Mutex::new(|record: &Record| {
            captured_logs.push(CapturedLog {
                body: format!("{}", record.args()).into(),
                level: record.level(),
                target: record.target().to_string().into(),
            });
        }),
    };
    let mut logger = EbpfLogger::init_with_logger(&mut bpf, &logger).unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_log_omission")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_ebpf_program", "/proc/self/exe", None, None)
        .unwrap();

    trigger_ebpf_program();
    logger.flush();

    let mut records = captured_logs.iter();
    assert_eq!(records.next(), None);
}
