//! modprobe is used to load kernel modules into the kernel.
//!
//! This implementation is incredibly naive and is only designed to work within
//! the constraints of the test environment. Not for production use.

use std::{
    fs::File,
    io::{BufRead as _, Read as _},
    path::Path,
};

use anyhow::{Context as _, anyhow, bail};
use clap::Parser;
use glob::glob;
use nix::kmod::init_module;
use test_distro::resolve_modules_dir;

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
    if let Err(e) = try_main(quiet, name) {
        if !quiet {
            return Err(e);
        } else {
            return Ok(());
        }
    }
    Ok(())
}

fn try_main(quiet: bool, name: String) -> anyhow::Result<()> {
    let modules_dir = resolve_modules_dir()?;

    output!(quiet, "resolving alias for module: {}", name);
    let module = resolve_alias(quiet, &modules_dir, &name)?;

    let pattern = format!(
        "{}/kernel/**/{}.ko*",
        modules_dir
            .to_str()
            .ok_or(anyhow!("failed to convert modules_dir to string"))?,
        module
    );
    let module_path = glob(&pattern)
        .with_context(|| format!("failed to glob: {}", pattern))?
        .find_map(Result::ok)
        .ok_or(anyhow!("module not found: {}", module))?;

    output!(quiet, "loading module: {}", module_path.display());
    let mut f =
        File::open(&module_path).with_context(|| format!("open(): {}", module_path.display()))?;

    let stat = f
        .metadata()
        .with_context(|| format!("stat(): {}", module_path.display()))?;

    let extension = module_path.as_path().extension().ok_or(anyhow!(
        "module has no extension: {}",
        module_path.display()
    ))?;

    let contents = if extension == "xz" {
        output!(quiet, "decompressing module");
        let mut decompressed = Vec::with_capacity(stat.len() as usize * 2);
        xz2::read::XzDecoder::new(f).read_to_end(&mut decompressed)?;
        decompressed
    } else {
        let mut contents: Vec<u8> = Vec::with_capacity(stat.len() as usize);
        f.read_to_end(&mut contents)?;
        contents
    };

    if !contents.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
        bail!("module is not an valid ELF file");
    }

    let res = init_module(&contents, c"");
    if let Err(e) = res {
        if e == nix::errno::Errno::EEXIST {
            bail!("module already loaded");
        }
        bail!("failed to load module: {}", e);
    }
    output!(quiet, "module loaded successfully");
    Ok(())
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
            let prefix = parts.next(); // skip "alias "
            if prefix != Some("alias") {
                bail!("alias line incorrect prefix: {}", line);
            }
            let alias = parts
                .next()
                .with_context(|| format!("alias line missing alias: {}", line))?;
            let module = parts
                .next()
                .with_context(|| format!("alias line missing module: {}", line))?;
            if alias == name {
                return Ok(module.to_string());
            }
        }
    }
    bail!("alias not found: {}", name)
}
