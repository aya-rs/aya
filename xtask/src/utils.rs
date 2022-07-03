use lazy_static::lazy_static;
use serde_json::Value;
use std::process::Command;

lazy_static! {
    pub static ref WORKSPACE_ROOT: String = workspace_root();
}

fn workspace_root() -> String {
    let output = Command::new("cargo").arg("metadata").output().unwrap();
    if !output.status.success() {
        panic!("unable to run cargo metadata")
    }
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: Value = serde_json::from_str(&stdout).unwrap();
    v["workspace_root"].as_str().unwrap().to_string()
}
