use std::{
    io::{self, Write},
    process::{Command, Output, Stdio},
};

pub fn format(code: &str) -> Result<String, io::Error> {
    let mut child = Command::new("rustfmt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let stdin = child.stdin.as_mut().unwrap();
    stdin.write_all(code.as_bytes())?;

    let Output {
        status,
        stdout,
        stderr,
    } = child.wait_with_output()?;
    if !status.success() {
        let stderr = String::from_utf8(stderr).unwrap();
        return Err(io::Error::other(format!(
            "rustfmt failed: {status:?}\n{stderr}"
        )));
    }
    Ok(String::from_utf8(stdout).unwrap())
}
