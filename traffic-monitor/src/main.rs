use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{HashMap, RingBuf},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::signal;

mod config;
mod event_handler;
mod ip_utils;
mod logger;

use config::{Config, TrafficMonitorConfig};
use event_handler::{EventHandler, TrafficEvent};
use ip_utils::parse_cidr;
use logger::{LogConfig, LogEntry, LogFormat, TrafficLoggerManager};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opt {
    #[arg(short, long, help = "Network interface to attach to")]
    interface: String,
    
    #[arg(short, long, help = "Configuration file path")]
    config: PathBuf,
    
    #[arg(long, help = "Drop non-permitted packets instead of just logging")]
    drop_packets: bool,
    
    #[arg(short, long, help = "Verbose logging")]
    verbose: bool,
    
    #[arg(long, help = "Log output format", value_enum, default_value = "console")]
    log_format: LogFormatArg,
    
    #[arg(long, help = "Log output file path (required for non-console formats)")]
    log_file: Option<PathBuf>,
    
    #[arg(long, help = "Log buffer size in bytes", default_value = "8192")]
    log_buffer_size: usize,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum LogFormatArg {
    Console,
    Json,
    Csv,
    Jsonl,
}

// Shared data structures with eBPF program
#[repr(C)]
struct EbpfConfig {
    drop_packets: u8,
}

#[repr(C)]
struct CidrRange {
    network: u32,
    prefix_len: u8,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    // Initialize logging
    env_logger::Builder::new()
        .filter_level(if opt.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .init();

    // Load configuration
    let config = TrafficMonitorConfig::load(&opt.config)
        .with_context(|| format!("Failed to load config from {:?}", opt.config))?;

    info!("Starting traffic monitor on interface: {}", opt.interface);
    info!("Loaded {} permitted CIDR ranges", config.permitted_cidrs.len());
    
    // Load eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/traffic-monitor"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/traffic-monitor"
    ))?;

    // Initialize eBPF logger
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Configure the eBPF program
    configure_ebpf_program(&mut bpf, &config, opt.drop_packets).await?;

    // Load and attach XDP program
    let program: &mut Xdp = bpf.program_mut("traffic_monitor").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.interface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("Traffic monitor attached to interface {} successfully", opt.interface);

    // Set up event handling
    let mut events: RingBuf<_> = bpf.take_map("EVENTS").unwrap().try_into()?;
    let mut event_handler = EventHandler::new();
    
    // Set up structured logging
    let log_config = LogConfig {
        format: match opt.log_format {
            LogFormatArg::Console => LogFormat::Console,
            LogFormatArg::Json => LogFormat::Json,
            LogFormatArg::Csv => LogFormat::Csv,
            LogFormatArg::Jsonl => LogFormat::JsonLines,
        },
        output_file: opt.log_file.clone(),
        buffer_size: Some(opt.log_buffer_size),
        rotate_size_mb: Some(100),
        max_files: Some(10),
    };
    
    let traffic_logger = TrafficLoggerManager::new(&log_config)
        .context("Failed to initialize traffic logger")?;
    
    info!("Initialized traffic logger with format: {:?}", log_config.format);
    if let Some(ref file) = log_config.output_file {
        info!("Logging to file: {:?}", file);
    }

    // Set up signal handling for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
        info!("Received Ctrl+C, shutting down...");
        r.store(false, Ordering::SeqCst);
    });

    info!("Traffic monitor is running. Press Ctrl+C to exit.");

    // Main event loop
    while running.load(Ordering::SeqCst) {
        // Process events from the ring buffer
        while let Some(item) = events.next() {
            let event: TrafficEvent = unsafe { std::ptr::read(item.as_ptr() as *const TrafficEvent) };
            
            // Log event with structured logger
            let log_entry = LogEntry::from_traffic_event(&event, &opt.interface);
            if let Err(e) = traffic_logger.log_event(&log_entry) {
                warn!("Failed to log event: {}", e);
            }
            
            // Process event for statistics
            event_handler.handle_event(event);
        }

        // Small delay to prevent busy waiting
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    // Flush any remaining log entries
    if let Err(e) = traffic_logger.flush() {
        warn!("Failed to flush log entries: {}", e);
    }
    
    info!("Traffic monitor shutdown complete");
    Ok(())
}

async fn configure_ebpf_program(
    bpf: &mut Ebpf,
    config: &TrafficMonitorConfig,
    drop_packets: bool,
) -> Result<()> {
    // Configure global settings
    let mut config_map: HashMap<_, u32, EbpfConfig> = bpf.take_map("CONFIG").unwrap().try_into()?;
    let ebpf_config = EbpfConfig {
        drop_packets: if drop_packets { 1 } else { 0 },
    };
    config_map.insert(0, ebpf_config, 0)?;

    // Load permitted CIDR ranges
    let mut cidrs_map: HashMap<_, u32, CidrRange> = bpf.take_map("PERMITTED_CIDRS").unwrap().try_into()?;
    
    for (index, cidr_str) in config.permitted_cidrs.iter().enumerate() {
        if let Ok((network, prefix_len)) = parse_cidr(cidr_str) {
            let cidr_range = CidrRange {
                network: u32::from(network).to_be(), // Convert to network byte order
                prefix_len,
            };
            cidrs_map.insert(index as u32, cidr_range, 0)?;
            info!("Added CIDR range {}: {}", index, cidr_str);
        } else {
            warn!("Failed to parse CIDR range: {}", cidr_str);
        }
    }

    info!(
        "Configured eBPF program with {} CIDR ranges, drop_packets: {}",
        config.permitted_cidrs.len(),
        drop_packets
    );

    Ok(())
}