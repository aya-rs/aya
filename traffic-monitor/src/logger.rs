use anyhow::{Context, Result};
use log::info;
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
    net::Ipv4Addr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::event_handler::TrafficEvent;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "csv")]
    Csv,
    #[serde(rename = "jsonl")]
    JsonLines,
    #[serde(rename = "console")]
    Console,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub format: LogFormat,
    pub output_file: Option<PathBuf>,
    pub buffer_size: Option<usize>,
    pub rotate_size_mb: Option<u64>,
    pub max_files: Option<u32>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Console,
            output_file: None,
            buffer_size: Some(8192),
            rotate_size_mb: Some(100),
            max_files: Some(10),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: u64,
    pub timestamp_iso: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub protocol_num: u8,
    pub packet_size: u16,
    pub action: String,
    pub interface: String,
    pub flow_hash: String,
}

impl LogEntry {
    pub fn from_traffic_event(event: &TrafficEvent, interface: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let timestamp_iso = chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .unwrap_or_default()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let src_ip = Ipv4Addr::from(u32::from_be(event.src_ip));
        let dst_ip = Ipv4Addr::from(u32::from_be(event.dst_ip));
        
        let protocol = protocol_to_string(event.protocol);
        let action = if event.action == 1 { "DROP" } else { "LOG" };
        
        // Create a flow hash for correlation
        let flow_hash = format!("{:08x}", 
            src_ip.octets().iter().fold(0u32, |acc, &x| acc.wrapping_mul(31).wrapping_add(x as u32))
                .wrapping_add(event.src_port as u32)
                .wrapping_add(event.protocol as u32)
        );

        Self {
            timestamp,
            timestamp_iso,
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol: protocol.to_string(),
            protocol_num: event.protocol,
            packet_size: event.packet_size,
            action: action.to_string(),
            interface: interface.to_string(),
            flow_hash,
        }
    }

    pub fn to_csv_header() -> String {
        "timestamp,timestamp_iso,src_ip,dst_ip,src_port,dst_port,protocol,protocol_num,packet_size,action,interface,flow_hash".to_string()
    }

    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            self.timestamp,
            self.timestamp_iso,
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.protocol,
            self.protocol_num,
            self.packet_size,
            self.action,
            self.interface,
            self.flow_hash
        )
    }
}

pub trait TrafficLogger: Send + Sync {
    fn log_event(&mut self, entry: &LogEntry) -> Result<()>;
    fn flush(&mut self) -> Result<()>;
}

pub struct ConsoleLogger;

impl TrafficLogger for ConsoleLogger {
    fn log_event(&mut self, entry: &LogEntry) -> Result<()> {
        if entry.src_port != 0 && entry.dst_port != 0 {
            info!(
                "[{}] Non-permitted traffic: {}:{} -> {}:{} (proto: {}, size: {} bytes, if: {})",
                entry.action, entry.src_ip, entry.src_port, entry.dst_ip, entry.dst_port,
                entry.protocol, entry.packet_size, entry.interface
            );
        } else {
            info!(
                "[{}] Non-permitted traffic: {} -> {} (proto: {}, size: {} bytes, if: {})",
                entry.action, entry.src_ip, entry.dst_ip, entry.protocol, entry.packet_size, entry.interface
            );
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

pub struct JsonLogger {
    writer: BufWriter<std::fs::File>,
    first_entry: bool,
}

impl JsonLogger {
    pub fn new(path: &PathBuf, buffer_size: usize) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open log file: {:?}", path))?;
        
        let writer = BufWriter::with_capacity(buffer_size, file);
        Ok(Self {
            writer,
            first_entry: true,
        })
    }

    fn ensure_array_start(&mut self) -> Result<()> {
        if self.first_entry {
            writeln!(self.writer, "[")?;
            self.first_entry = false;
        }
        Ok(())
    }
}

impl TrafficLogger for JsonLogger {
    fn log_event(&mut self, entry: &LogEntry) -> Result<()> {
        self.ensure_array_start()?;
        
        let json = serde_json::to_string(entry)
            .context("Failed to serialize log entry to JSON")?;
        
        writeln!(self.writer, "  {},", json)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if !self.first_entry {
            // Close the JSON array
            writeln!(self.writer, "]")?;
        }
        self.writer.flush()?;
        Ok(())
    }
}

pub struct JsonLinesLogger {
    writer: BufWriter<std::fs::File>,
}

impl JsonLinesLogger {
    pub fn new(path: &PathBuf, buffer_size: usize) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open log file: {:?}", path))?;
        
        let writer = BufWriter::with_capacity(buffer_size, file);
        Ok(Self { writer })
    }
}

impl TrafficLogger for JsonLinesLogger {
    fn log_event(&mut self, entry: &LogEntry) -> Result<()> {
        let json = serde_json::to_string(entry)
            .context("Failed to serialize log entry to JSON")?;
        
        writeln!(self.writer, "{}", json)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}

pub struct CsvLogger {
    writer: BufWriter<std::fs::File>,
    header_written: bool,
}

impl CsvLogger {
    pub fn new(path: &PathBuf, buffer_size: usize) -> Result<Self> {
        let file_exists = path.exists();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open log file: {:?}", path))?;
        
        let writer = BufWriter::with_capacity(buffer_size, file);
        Ok(Self {
            writer,
            header_written: file_exists,
        })
    }

    fn ensure_header(&mut self) -> Result<()> {
        if !self.header_written {
            writeln!(self.writer, "{}", LogEntry::to_csv_header())?;
            self.header_written = true;
        }
        Ok(())
    }
}

impl TrafficLogger for CsvLogger {
    fn log_event(&mut self, entry: &LogEntry) -> Result<()> {
        self.ensure_header()?;
        writeln!(self.writer, "{}", entry.to_csv_row())?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}

pub struct TrafficLoggerManager {
    logger: Arc<Mutex<Box<dyn TrafficLogger>>>,
}

impl TrafficLoggerManager {
    pub fn new(config: &LogConfig) -> Result<Self> {
        let logger: Box<dyn TrafficLogger> = match (&config.format, &config.output_file) {
            (LogFormat::Console, _) => Box::new(ConsoleLogger),
            (LogFormat::Json, Some(path)) => {
                Box::new(JsonLogger::new(path, config.buffer_size.unwrap_or(8192))?)
            }
            (LogFormat::JsonLines, Some(path)) => {
                Box::new(JsonLinesLogger::new(path, config.buffer_size.unwrap_or(8192))?)
            }
            (LogFormat::Csv, Some(path)) => {
                Box::new(CsvLogger::new(path, config.buffer_size.unwrap_or(8192))?)
            }
            (format, None) => {
                return Err(anyhow::anyhow!(
                    "Output file required for format: {:?}",
                    format
                ))
            }
        };

        Ok(Self {
            logger: Arc::new(Mutex::new(logger)),
        })
    }

    pub fn log_event(&self, entry: &LogEntry) -> Result<()> {
        let mut logger = self.logger.lock().unwrap();
        logger.log_event(entry)
    }

    pub fn flush(&self) -> Result<()> {
        let mut logger = self.logger.lock().unwrap();
        logger.flush()
    }
}

fn protocol_to_string(protocol: u8) -> &'static str {
    match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        132 => "SCTP",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_log_entry_serialization() {
        let event = TrafficEvent {
            src_ip: u32::from(Ipv4Addr::new(8, 8, 8, 8)).to_be(),
            dst_ip: u32::from(Ipv4Addr::new(192, 168, 1, 100)).to_be(),
            src_port: 53,
            dst_port: 12345,
            protocol: 17,
            packet_size: 128,
            action: 0,
        };

        let entry = LogEntry::from_traffic_event(&event, "eth0");
        
        assert_eq!(entry.src_ip, "8.8.8.8");
        assert_eq!(entry.dst_ip, "192.168.1.100");
        assert_eq!(entry.protocol, "UDP");
        assert_eq!(entry.action, "LOG");
        assert_eq!(entry.interface, "eth0");
    }

    #[test]
    fn test_csv_logger() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        let mut logger = CsvLogger::new(&temp_file.path().to_path_buf(), 1024)?;

        let event = TrafficEvent {
            src_ip: u32::from(Ipv4Addr::new(1, 1, 1, 1)).to_be(),
            dst_ip: u32::from(Ipv4Addr::new(192, 168, 1, 1)).to_be(),
            src_port: 443,
            dst_port: 54321,
            protocol: 6,
            packet_size: 1500,
            action: 1,
        };

        let entry = LogEntry::from_traffic_event(&event, "wlan0");
        logger.log_event(&entry)?;
        logger.flush()?;

        let content = std::fs::read_to_string(temp_file.path())?;
        assert!(content.contains("timestamp,timestamp_iso"));
        assert!(content.contains("1.1.1.1,192.168.1.1"));
        assert!(content.contains("TCP"));
        assert!(content.contains("DROP"));

        Ok(())
    }

    #[test]
    fn test_jsonl_logger() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        let mut logger = JsonLinesLogger::new(&temp_file.path().to_path_buf(), 1024)?;

        let event = TrafficEvent {
            src_ip: u32::from(Ipv4Addr::new(1, 1, 1, 1)).to_be(),
            dst_ip: u32::from(Ipv4Addr::new(192, 168, 1, 1)).to_be(),
            src_port: 443,
            dst_port: 54321,
            protocol: 6,
            packet_size: 1500,
            action: 0,
        };

        let entry = LogEntry::from_traffic_event(&event, "wlan0");
        logger.log_event(&entry)?;
        logger.flush()?;

        let content = std::fs::read_to_string(temp_file.path())?;
        let parsed: LogEntry = serde_json::from_str(content.trim())?;
        
        assert_eq!(parsed.src_ip, "1.1.1.1");
        assert_eq!(parsed.protocol, "TCP");
        assert_eq!(parsed.action, "LOG");

        Ok(())
    }
}