//! Validates BPF token support end-to-end.
//! Run as root for full validation. As unprivileged user, validates error paths.

use std::{fs, os::fd::{AsFd as _, AsRawFd as _}, process::Command};

use aya::{
    maps::MapData,
    token::{BpfToken, FilesystemPermissionsBuilder, create_bpf_filesystem},
    util::KernelVersion,
};
use aya_obj::cmd::BpfCommand;

const BPFFS_PATH: &str = "/tmp/aya-validate-bpffs";

fn cleanup() {
    let _ = Command::new("umount").arg(BPFFS_PATH).output();
    let _ = fs::remove_dir(BPFFS_PATH);
}

fn main() {
    println!("=== BPF Token Validation ===\n");

    // [1] Check kernel version
    let version = KernelVersion::current().unwrap();
    println!("[1] Kernel version: {version:?}");
    if version < KernelVersion::new(6, 9, 0) {
        println!("    SKIP: BPF token requires kernel >= 6.9");
        return;
    }
    println!("    OK (>= 6.9)\n");

    // [2] Error path: token on non-BPFFS
    print!("[2] BpfToken::create on /tmp (non-BPFFS)... ");
    match BpfToken::create("/tmp") {
        Err(e) => println!("OK (correctly failed: {e})"),
        Ok(_) => println!("UNEXPECTED: should have failed"),
    }

    // [3] Error path: token on nonexistent path
    print!("[3] BpfToken::create on nonexistent path... ");
    match BpfToken::create("/nonexistent/path") {
        Err(e) => println!("OK (correctly failed: {e})"),
        Ok(_) => println!("UNEXPECTED: should have failed"),
    }

    // [4] Try to create BPFFS (needs root)
    cleanup();
    fs::create_dir_all(BPFFS_PATH).unwrap();
    // Note: do NOT include BpfCommand::TokenCreate in delegate_cmds.
    // TOKEN_CREATE is not a delegated command - it's always available
    // as long as the BPFFS has at least one delegation option set.
    let perms = FilesystemPermissionsBuilder::default()
        .allow_cmd(BpfCommand::MapCreate)
        .allow_cmd(BpfCommand::ProgLoad)
        .allow_cmd(BpfCommand::BtfLoad)
        .build();

    print!("\n[4] Creating BPFFS at {BPFFS_PATH}... ");
    let can_mount = match create_bpf_filesystem(BPFFS_PATH, perms) {
        Ok(()) => {
            println!("OK");
            let mounts = fs::read_to_string("/proc/mounts").unwrap();
            println!("    Mount verified: {}", mounts.contains(BPFFS_PATH));
            true
        }
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
            println!("SKIP (need root)");
            false
        }
        Err(e) => {
            println!("FAIL: {e}");
            cleanup();
            std::process::exit(1);
        }
    };

    if !can_mount {
        cleanup();
        println!("\n=== Unprivileged validation complete. Run as root for full test. ===");
        return;
    }

    // [5] Create token
    print!("[5] Creating BPF token... ");
    let token = match BpfToken::create(BPFFS_PATH) {
        Ok(t) => {
            println!("OK (fd={})", t.as_fd().as_raw_fd());
            t
        }
        Err(e) if e.raw_os_error() == Some(95) => {
            // EOPNOTSUPP: AppArmor 4.x blocks BPF_TOKEN_CREATE when
            // AA_CLASS_BPF_TOKEN is not mediated (even unconfined profile).
            // Boot with apparmor=0 to bypass.
            println!("SKIP (blocked by LSM/AppArmor: {e})");
            println!("\n      AppArmor 4.x on Ubuntu 24.10+ blocks BPF_TOKEN_CREATE.");
            println!("      Boot with 'apparmor=0' kernel param to test fully.");
            println!("\n=== Partial validation passed (BPFFS mount OK, token blocked by LSM). ===");
            cleanup();
            return;
        }
        Err(e) => {
            println!("FAIL: {e}");
            cleanup();
            std::process::exit(1);
        }
    };

    // [6] Feature detection with token
    print!("[6] Feature detection with token... ");
    let features = aya::sys::detect_features_with_token(token.as_fd());
    println!("OK");
    println!(
        "    bpf_name={}, probe_read_kernel={}, perf_link={}, global_data={}",
        features.bpf_name(),
        features.bpf_probe_read_kernel(),
        features.bpf_perf_link(),
        features.bpf_global_data(),
    );
    if let Some(btf) = features.btf() {
        println!(
            "    btf: func={}, func_global={}, datasec={}, float={}, enum64={}",
            btf.btf_func(),
            btf.btf_func_global(),
            btf.btf_datasec(),
            btf.btf_float(),
            btf.btf_enum64(),
        );
    }

    // [7] Create a map using the token
    print!("[7] Creating BPF map with token... ");
    let map = MapData::create(
        aya_obj::Map::Legacy(aya_obj::maps::LegacyMap {
            def: aya_obj::maps::bpf_map_def {
                map_type: aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
                key_size: 4,
                value_size: 4,
                max_entries: 1,
                ..Default::default()
            },
            section_index: 0,
            section_kind: aya_obj::EbpfSectionKind::Maps,
            symbol_index: None,
            data: Vec::new(),
        }),
        "aya_token_test",
        None,
        Some(token.as_fd()),
        features.clone(),
    );
    match map {
        Ok(m) => println!("OK (fd={})", m.fd().as_fd().as_raw_fd()),
        Err(e) => {
            println!("FAIL: {e}");
            cleanup();
            std::process::exit(1);
        }
    }

    // [8] Multiple tokens from same BPFFS
    print!("[8] Creating second token from same BPFFS... ");
    let token2 = BpfToken::create(BPFFS_PATH).unwrap();
    assert_ne!(token.as_fd().as_raw_fd(), token2.as_fd().as_raw_fd());
    println!("OK (fd={}, different from first)", token2.as_fd().as_raw_fd());

    cleanup();
    println!("\n=== All checks passed! BPF token support is working. ===");
}
