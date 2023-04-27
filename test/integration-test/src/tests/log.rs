use std::sync::{Arc, LockResult, Mutex, MutexGuard};

use aya::{include_bytes_aligned, programs::UProbe, Bpf};
use aya_log::BpfLogger;
use log::{Level, Log, Record};
use tokio::time::{sleep, Duration};

use super::tokio_integration_test;

const MAX_ATTEMPTS: usize = 10;
const TIMEOUT_MS: u64 = 10;

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_ebpf_program() {}

struct CapturedLogs(Arc<Mutex<Vec<CapturedLog>>>);

impl CapturedLogs {
    fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(Vec::with_capacity(capacity))))
    }

    fn clone(&self) -> Self {
        Self(self.0.clone())
    }

    fn lock(&self) -> LockResult<MutexGuard<'_, Vec<CapturedLog>>> {
        self.0.lock()
    }

    async fn wait_expected_len(&self, expected_len: usize) {
        for _ in 0..MAX_ATTEMPTS {
            {
                let captured_logs = self.0.lock().expect("Failed to lock captured logs");
                if captured_logs.len() == expected_len {
                    return;
                }
            }
            sleep(Duration::from_millis(TIMEOUT_MS)).await;
        }
        panic!(
            "Expected {} captured logs, but got {}",
            expected_len,
            self.0.lock().unwrap().len()
        );
    }
}

struct CapturedLog {
    pub body: String,
    pub level: Level,
    pub target: String,
}

struct TestingLogger {
    captured_logs: CapturedLogs,
}

impl TestingLogger {
    pub fn with_capacity(capacity: usize) -> (Self, CapturedLogs) {
        let captured_logs = CapturedLogs::with_capacity(capacity);
        (
            Self {
                captured_logs: captured_logs.clone(),
            },
            captured_logs,
        )
    }
}

impl Log for TestingLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn flush(&self) {}

    fn log(&self, record: &Record) {
        let captured_record = CapturedLog {
            body: format!("{}", record.args()),
            level: record.level(),
            target: record.target().to_string(),
        };
        self.captured_logs
            .lock()
            .expect("Failed to acquire a lock for storing a log")
            .push(captured_record);
    }
}

#[tokio_integration_test]
async fn log() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/release/log");
    let mut bpf = Bpf::load(bytes).unwrap();

    let (logger, captured_logs) = TestingLogger::with_capacity(5);
    BpfLogger::init_with_logger(&mut bpf, logger).unwrap();

    let prog: &mut UProbe = bpf.program_mut("test_log").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach(Some("trigger_ebpf_program"), 0, "/proc/self/exe", None)
        .unwrap();

    // Call the function that the uprobe is attached to, so it starts logging.
    trigger_ebpf_program();
    captured_logs.wait_expected_len(5).await;

    let records = captured_logs
        .lock()
        .expect("Failed to acquire a lock for reading logs");
    assert_eq!(records.len(), 5);

    assert_eq!(records[0].body, "Hello from eBPF!");
    assert_eq!(records[0].level, Level::Debug);
    assert_eq!(records[0].target, "log");

    assert_eq!(records[1].body, "69, 420, wao");
    assert_eq!(records[1].level, Level::Error);
    assert_eq!(records[1].target, "log");

    assert_eq!(records[2].body, "ipv4: 10.0.0.1, ipv6: 2001:db8::1");
    assert_eq!(records[2].level, Level::Info);
    assert_eq!(records[2].target, "log");

    assert_eq!(
        records[3].body,
        "mac lc: 04:20:06:09:00:40, mac uc: 04:20:06:09:00:40"
    );
    assert_eq!(records[3].level, Level::Trace);
    assert_eq!(records[3].target, "log");

    assert_eq!(records[4].body, "hex lc: 2f, hex uc: 2F");
    assert_eq!(records[4].level, Level::Warn);
    assert_eq!(records[4].target, "log");
}
