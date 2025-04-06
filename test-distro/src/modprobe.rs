//! modprobe is used to load kernel modules into the kernel.
//!
//! This implementation is incredibly naive and is only designed to work within
//! the constraints of the test environment. Not for production use.

use std::{fs::File, io::BufRead as _, path::Path};

use anyhow::{Context as _, anyhow, bail};
use clap::Parser;
use glob::glob;
use nix::kmod::init_module;
use test_distro::{read_to_end, resolve_modules_dir};

macro_rules! output {
    ($quiet:expr, $($arg:tt)*) => {
        if !$quiet {
            println!($($arg)*);
        }
    };
}

#[derive(Parser)]
struct Args {
    /// Suppress all output and don't return an error code.
    #[clap(short, long, default_value = "false")]
    quiet: bool,

    /// The name of the module to load.
    /// This can be either an alias like `net-sched-sch-ingress` or a module
    /// name like `sch_ingress`.
    name: String,
}

fn main() -> anyhow::Result<()> {
    let Args { quiet, name } = Parser::parse();
    let ret = try_main(quiet, name);
    if quiet { Ok(()) } else { ret }
}

fn try_main(quiet: bool, name: String) -> anyhow::Result<()> {
    let modules_dir = resolve_modules_dir()?;

    output!(quiet, "resolving alias for module: {}", name);
    let module = resolve_alias(quiet, &modules_dir, &name)?;

    let pattern = format!(
        "{}/kernel/**/{}.ko*",
        modules_dir
            .to_str()
            .ok_or_else(|| anyhow!("failed to convert {} to string", modules_dir.display()))?,
        module
    );
    let module_path = glob(&pattern)
        .with_context(|| format!("failed to glob: {}", pattern))?
        .next()
        .ok_or_else(|| anyhow!("module not found: {}", module))?
        .context("glob error")?;

    output!(quiet, "loading module: {}", module_path.display());

    let extension = module_path
        .as_path()
        .extension()
        .ok_or_else(|| anyhow!("module has no extension: {}", module_path.display()))?;

    let contents = read_to_end(&module_path, extension == "xz")
        .with_context(|| format!("read_to_end({})", module_path.display()))?;

    if !contents.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
        bail!("module is not an valid ELF file");
    }

    match init_module(&contents, c"") {
        Ok(()) => {
            output!(quiet, "module loaded successfully");
            Ok(())
        }
        Err(e) => {
            if e == nix::errno::Errno::EEXIST {
                Err(anyhow!("module already loaded"))
            } else {
                Err(anyhow!("failed to load module: {}", e))
            }
        }
    }
}

fn resolve_alias(quiet: bool, module_dir: &Path, name: &str) -> anyhow::Result<String> {
    let modules_alias = module_dir.join("modules.alias");
    output!(
        quiet,
        "opening modules.alias file: {}",
        modules_alias.display()
    );
    let alias_file = File::open(&modules_alias)
        .with_context(|| format!("open(): {}", modules_alias.display()))?;
    let alias_file = std::io::BufReader::new(alias_file);

    for line in alias_file.lines() {
        let line = line?;
        if line.starts_with("alias ") {
            let mut parts = line.split_whitespace();
            let prefix = parts.next();
            if prefix != Some("alias") {
                bail!("alias line incorrect prefix: {}", line);
            }
            let alias = parts
                .next()
                .with_context(|| format!("alias line missing alias: {}", line))?;
            let module = parts
                .next()
                .with_context(|| format!("alias line missing module: {}", line))?;
            if parts.next().is_some() {
                bail!("alias line has too many parts: {}", line);
            }
            if alias == name {
                return Ok(module.to_string());
            }
        }
    }
    bail!("alias not found: {}", name)
}
