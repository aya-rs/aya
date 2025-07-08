use aya_build::EbpfBuilder;

fn main() {
    EbpfBuilder::new()
        .file("src/traffic_monitor.bpf.rs")
        .build()
        .unwrap();
}