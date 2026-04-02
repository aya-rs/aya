use std::{
    convert::TryInto as _,
    fs,
    os::fd::{AsFd as _, AsRawFd as _},
    process::Command,
};

use aya::{
    EbpfLoader,
    maps::MapData,
    programs::{Xdp, XdpFlags},
    token::{BpfToken, FilesystemPermissionsBuilder, create_bpf_filesystem},
    util::KernelVersion,
};
use aya_obj::{cmd::BpfCommand, maps::BpfMapType, programs::BpfProgType};

fn cleanup(path: &str) {
    drop(Command::new("umount").arg(path).output());
    drop(fs::remove_dir(path));
}

fn require_kernel_6_9() -> bool {
    let version = KernelVersion::current().unwrap();
    if version < KernelVersion::new(6, 9, 0) {
        eprintln!("skipping BPF token test on kernel {version:?}, BPF token requires >= 6.9");
        return false;
    }
    true
}

/// Try to create a BPF token from the given path.
/// Returns None (skip) if blocked by an LSM like AppArmor 4.x (EOPNOTSUPP).
fn try_create_token(path: &str) -> Option<BpfToken> {
    match BpfToken::create(path) {
        Ok(token) => Some(token),
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
            // AppArmor 4.x on Ubuntu 24.10+ returns EOPNOTSUPP when
            // BPF token class is not mediated in the profile (even unconfined).
            // Boot with apparmor=0 to bypass.
            eprintln!("skipping: BPF token blocked by LSM (EOPNOTSUPP)");
            None
        }
        Err(e) => panic!("BpfToken::create failed unexpectedly: {e}"),
    }
}

/// Helper: mount a BPFFS with given permissions, skip test on EPERM.
/// Returns None if the test should be skipped.
fn setup_bpffs(path: &str, perms: aya::token::FilesystemPermissions) -> Option<()> {
    cleanup(path);
    fs::create_dir_all(path).unwrap();
    match create_bpf_filesystem(path, perms) {
        Ok(()) => Some(()),
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
            cleanup(path);
            eprintln!("skipping: insufficient privileges to mount BPFFS");
            None
        }
        Err(e) => {
            cleanup(path);
            panic!("create_bpf_filesystem failed: {e}");
        }
    }
}

// ---- Kernel selftest: userns_map_create ----
// Tests the full token → map creation path.
// In the kernel selftest this is done inside a user namespace to verify
// that token + CAP_BPF are both required. Here we test the API end-to-end.

/// Mirrors kernel selftest `userns_map_create`:
/// create a BPFFS with MAP_CREATE delegation, obtain token, create map.
#[test_log::test]
fn token_map_create() {
    if !require_kernel_6_9() {
        return;
    }

    let path = "/tmp/aya-test-token-map-create";
    let perms = FilesystemPermissionsBuilder::default()
        .allow_cmd(BpfCommand::MapCreate)
        .allow_map_type(BpfMapType::Array)
        .build();

    if setup_bpffs(path, perms).is_none() {
        return;
    }

    let Some(token) = try_create_token(path) else {
        cleanup(path);
        return;
    };

    // Create a simple array map using the token (like userns_map_create creating a STACK map).
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
        "aya_token_map",
        None,
        Some(token.as_fd()),
        Default::default(),
    )
    .unwrap();

    assert!(map.fd().as_fd().as_raw_fd() >= 0, "map fd should be valid");
    cleanup(path);
}

// ---- Kernel selftest: userns_btf_load ----
// Tests that BTF can be loaded using a token with BPF_BTF_LOAD delegated.

/// Mirrors kernel selftest `userns_btf_load`:
/// create a BPFFS with BTF_LOAD delegation, obtain token, load BTF via EbpfLoader.
#[test_log::test]
fn token_btf_load() {
    if !require_kernel_6_9() {
        return;
    }

    let path = "/tmp/aya-test-token-btf-load";
    let perms = FilesystemPermissionsBuilder::default()
        .allow_cmd(BpfCommand::MapCreate)
        .allow_cmd(BpfCommand::ProgLoad)
        .allow_cmd(BpfCommand::BtfLoad)
        .build();

    if setup_bpffs(path, perms).is_none() {
        return;
    }

    let Some(token) = try_create_token(path) else {
        cleanup(path);
        return;
    };

    // Load a program that has BTF. If BTF loading via token works,
    // the program will load successfully (BTF is loaded as part of the
    // EbpfLoader::load() pipeline).
    let bpf = EbpfLoader::new().token(&token).load(crate::PASS);
    assert!(
        bpf.is_ok(),
        "EbpfLoader with token should load BTF successfully"
    );

    cleanup(path);
}

// ---- Kernel selftest: userns_prog_load ----
// Tests program loading with token and verifying the program is functional.

/// Mirrors kernel selftest `userns_prog_load`:
/// load an XDP program using token, then attach it.
#[test_log::test]
fn token_prog_load_and_attach() {
    if !require_kernel_6_9() {
        return;
    }

    let path = "/tmp/aya-test-token-prog-load";
    let perms = FilesystemPermissionsBuilder::default()
        .allow_cmd(BpfCommand::MapCreate)
        .allow_cmd(BpfCommand::ProgLoad)
        .allow_cmd(BpfCommand::BtfLoad)
        .allow_prog_type(BpfProgType::Xdp)
        .build();

    if setup_bpffs(path, perms).is_none() {
        return;
    }

    let Some(token) = try_create_token(path) else {
        cleanup(path);
        return;
    };

    let mut bpf = EbpfLoader::new().token(&token).load(crate::PASS).unwrap();
    let prog: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("lo", XdpFlags::default()).unwrap();

    cleanup(path);
}

// ---- Kernel selftest: feature detection with token ----
// The kernel selftest doesn't test this directly, but it's the foundation:
// feature detection should work with a token_fd.

/// Tests that detect_features_with_token produces valid features.
#[test_log::test]
fn token_feature_detection() {
    if !require_kernel_6_9() {
        return;
    }

    let path = "/tmp/aya-test-token-features";
    let perms = FilesystemPermissionsBuilder::default()
        .allow_cmd(BpfCommand::MapCreate)
        .allow_cmd(BpfCommand::ProgLoad)
        .allow_cmd(BpfCommand::BtfLoad)
        .build();

    if setup_bpffs(path, perms).is_none() {
        return;
    }

    let Some(token) = try_create_token(path) else {
        cleanup(path);
        return;
    };

    // Run feature detection with the token.
    let features = aya::sys::detect_features_with_token(token.as_fd());

    // On a kernel >= 6.9, basic features should be detected.
    // We don't assert specific values because it depends on kernel config,
    // but the features struct should be successfully created.
    // At minimum, prog_name support (kernel 4.15+) should be true.
    assert!(
        features.bpf_name(),
        "bpf_name should be supported on kernel >= 6.9"
    );

    cleanup(path);
}

// ---- Kernel selftest: create_bpffs_fd + materialize_bpffs_fd ----
// Tests the BPFFS creation and mount sequence.

/// Tests that create_bpf_filesystem produces a valid BPFFS mount,
/// mirroring the kernel selftest's create_bpffs_fd() + materialize_bpffs_fd()
/// + sys_fsmount() + sys_move_mount() sequence.
#[test_log::test]
fn token_bpffs_mount() {
    if !require_kernel_6_9() {
        return;
    }

    let path = "/tmp/aya-test-token-bpffs-mount";
    let perms = FilesystemPermissionsBuilder::default()
        .allow_cmd(BpfCommand::MapCreate)
        .build();

    if setup_bpffs(path, perms).is_none() {
        return;
    }

    // Verify the mount exists.
    let mounts = fs::read_to_string("/proc/mounts").unwrap();
    assert!(mounts.contains(path), "BPFFS should be mounted at {path}");

    // Verify we can create a token from it (may be blocked by LSM).
    match BpfToken::create(path) {
        Ok(token) => assert!(token.as_fd().as_raw_fd() >= 0),
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
            eprintln!("skipping token check: blocked by LSM (EOPNOTSUPP)");
        }
        Err(e) => panic!("BpfToken::create failed: {e}"),
    }

    cleanup(path);
}

// ---- Kernel selftest: bpf_token_create directly ----
// Tests the raw BPF_TOKEN_CREATE syscall.

/// Tests BPF token creation directly from a BPFFS,
/// mirroring the kernel selftest's bpf_token_create() call.
#[test_log::test]
fn token_direct_create() {
    if !require_kernel_6_9() {
        return;
    }

    let path = "/tmp/aya-test-token-direct-create";
    let perms = FilesystemPermissionsBuilder::default().build();

    if setup_bpffs(path, perms).is_none() {
        return;
    }

    let Some(token) = try_create_token(path) else {
        cleanup(path);
        return;
    };
    assert!(token.as_fd().as_raw_fd() >= 0, "token fd should be valid");

    cleanup(path);
}

// ---- Error path tests (not in kernel selftest but important for robustness) ----

/// Tests that BpfToken::create fails gracefully on a non-existent path.
#[test_log::test]
fn token_create_nonexistent_path() {
    if !require_kernel_6_9() {
        return;
    }

    let result = BpfToken::create("/nonexistent/bpffs/path");
    assert!(
        result.is_err(),
        "BpfToken::create should fail for nonexistent path"
    );
}

/// Tests that BpfToken::create fails on a regular directory (not a BPFFS).
#[test_log::test]
fn token_create_non_bpffs() {
    if !require_kernel_6_9() {
        return;
    }

    let result = BpfToken::create("/tmp");
    assert!(result.is_err(), "BpfToken::create should fail on non-BPFFS");
}

// ---- Kernel selftest: multiple tokens from same BPFFS ----
// The kernel selftest creates multiple tokens in different subtests from
// the same BPFFS. Let's verify this works.

/// Tests that multiple tokens can be created from the same BPFFS,
/// like the kernel selftest does across its subtests.
#[test_log::test]
fn token_multiple_from_same_bpffs() {
    if !require_kernel_6_9() {
        return;
    }

    let path = "/tmp/aya-test-token-multi";
    let perms = FilesystemPermissionsBuilder::default()
        .allow_cmd(BpfCommand::MapCreate)
        .allow_cmd(BpfCommand::ProgLoad)
        .allow_cmd(BpfCommand::BtfLoad)
        .build();

    if setup_bpffs(path, perms).is_none() {
        return;
    }

    let Some(token1) = try_create_token(path) else {
        cleanup(path);
        return;
    };
    let Some(token2) = try_create_token(path) else {
        cleanup(path);
        return;
    };

    // Both tokens should be valid and have different fds.
    assert!(token1.as_fd().as_raw_fd() >= 0);
    assert!(token2.as_fd().as_raw_fd() >= 0);
    assert_ne!(
        token1.as_fd().as_raw_fd(),
        token2.as_fd().as_raw_fd(),
        "different tokens should have different fds"
    );

    // Both should work for loading.
    let bpf1 = EbpfLoader::new().token(&token1).load(crate::PASS);
    assert!(bpf1.is_ok(), "first token should work for loading");

    let bpf2 = EbpfLoader::new().token(&token2).load(crate::PASS);
    assert!(bpf2.is_ok(), "second token should work for loading");

    cleanup(path);
}

// ---- Kernel selftest: delegation mask variations ----
// userns_obj_priv_btf_fail tests that without BPF_BTF_LOAD in delegate_cmds,
// loading an object requiring BTF fails.
// userns_obj_priv_btf_success tests the opposite.
// We can't test failure in a privileged context (root can always load BTF),
// but we can test that different delegation masks produce valid tokens.

/// Tests that a BPFFS with all delegation masks set works for full program loading.
/// Mirrors userns_obj_priv_btf_success: all commands delegated → success.
#[test_log::test]
fn token_full_delegation() {
    if !require_kernel_6_9() {
        return;
    }

    let path = "/tmp/aya-test-token-full-deleg";
    let perms = FilesystemPermissionsBuilder::default()
        .allow_cmd(BpfCommand::MapCreate)
        .allow_cmd(BpfCommand::ProgLoad)
        .allow_cmd(BpfCommand::BtfLoad)
        .allow_cmd(BpfCommand::ProgGetFdById)
        .allow_cmd(BpfCommand::MapGetFdById)
        .allow_cmd(BpfCommand::ObjPin)
        .allow_cmd(BpfCommand::ObjGet)
        .allow_prog_type(BpfProgType::Xdp)
        .allow_prog_type(BpfProgType::SocketFilter)
        .allow_map_type(BpfMapType::Array)
        .allow_map_type(BpfMapType::Hash)
        .build();

    if setup_bpffs(path, perms).is_none() {
        return;
    }

    let Some(token) = try_create_token(path) else {
        cleanup(path);
        return;
    };
    let bpf = EbpfLoader::new().token(&token).load(crate::PASS);
    assert!(bpf.is_ok(), "full delegation should allow program loading");

    cleanup(path);
}

/// Tests uid/gid options on FilesystemPermissionsBuilder.
#[test_log::test]
fn token_bpffs_with_uid_gid() {
    if !require_kernel_6_9() {
        return;
    }

    let path = "/tmp/aya-test-token-uidgid";
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let perms = FilesystemPermissionsBuilder::default()
        .uid(uid)
        .gid(gid)
        .build();

    if setup_bpffs(path, perms).is_none() {
        return;
    }

    // Should be able to create a token from the BPFFS owned by our uid/gid
    // (may be blocked by LSM).
    match BpfToken::create(path) {
        Ok(token) => assert!(token.as_fd().as_raw_fd() >= 0),
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
            eprintln!("skipping token check: blocked by LSM");
        }
        Err(e) => panic!("BpfToken::create failed: {e}"),
    }

    cleanup(path);
}
