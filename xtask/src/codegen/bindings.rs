use std::{
    fs::File,
    io::{self, Write},
    path::Path,
    process::Command,
};

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

pub fn write(bindings: &str, header: &str, filename: &Path) -> io::Result<()> {
    let mut file = File::create(&filename)?;
    file.write(header.as_bytes())?;
    file.write(bindings.as_bytes())?;

    Command::new("rustfmt").arg(filename).status()?;
    Ok(())
}
