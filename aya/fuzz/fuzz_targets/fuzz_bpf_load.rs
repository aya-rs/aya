#![no_main]
use aya::Bpf;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Bpf::load(data);
});
