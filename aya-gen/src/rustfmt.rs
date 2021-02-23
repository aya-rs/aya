use std::{
    io::{self, Write},
    process::{Command, Stdio},
};

pub fn format(code: &str) -> Result<String, io::Error> {
    let mut child = Command::new("rustfmt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let stdin = child.stdin.as_mut().unwrap();
    stdin.write_all(code.as_bytes())?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "rustfmt failed with exit code: {}",
                output.status.code().unwrap()
            ),
        ));
    }
    Ok(String::from_utf8(output.stdout).unwrap())
}
