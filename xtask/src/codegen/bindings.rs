use std::process::Command;

pub fn bindgen(types: &[&str], vars: &[&str]) -> Command {
    let mut cmd = Command::new("bindgen");
    cmd.arg("--no-layout-tests")
        .arg("--use-core")
        .arg("--ctypes-prefix")
        .arg("::aya_bpf_cty")
        .arg("--default-enum-style")
        .arg("consts")
        .arg("--no-prepend-enum-name");

    for x in types {
        cmd.arg("--whitelist-type").arg(x);
    }

    for x in vars {
        cmd.arg("--whitelist-var").arg(x);
    }

    cmd
}
