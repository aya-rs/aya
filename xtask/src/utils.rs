use serde_json::Value;
use std::{cell::OnceCell, process::Command};

pub fn workspace_root() -> &'static str {
    static mut WORKSPACE_ROOT: OnceCell<String> = OnceCell::new();
    unsafe { &mut WORKSPACE_ROOT }.get_or_init(|| {
        let output = Command::new("cargo").arg("metadata").output().unwrap();
        if !output.status.success() {
            panic!("unable to run cargo metadata")
        }
        let stdout = String::from_utf8(output.stdout).unwrap();
        let v: Value = serde_json::from_str(&stdout).unwrap();
        v["workspace_root"].as_str().unwrap().to_string()
    })
}
