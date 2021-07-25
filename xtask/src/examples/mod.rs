use std::path::PathBuf;
use std::process::Command;

use structopt::StructOpt;

#[derive(StructOpt)]
pub struct Options {}

pub fn examples(_opts: Options) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("examples");
    
    // build bpf examples
    let status = Command::new("cargo")
        .current_dir(&dir)
        .args(&["+nightly", "build", "--verbose", "--release", "--package=bpf", "--target=bpfel-unknown-none", "-Z", "build-std=core"])
        .status()
        .expect("failed to build bpf examples");
    assert!(status.success());
    
    // build userspace examples
    let status = Command::new("cargo")
        .current_dir(&dir)
        .args(&["build", "--verbose", "--package=user"])
        .status()
        .expect("failed to build userspace examples");
    assert!(status.success());
    
    Ok(())
}
