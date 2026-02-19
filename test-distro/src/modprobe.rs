//! modprobe is used to load kernel modules into the kernel.
//!
//! This implementation is incredibly naive and is only designed to work within
//! the constraints of the test environment. Not for production use.

use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::File,
    io::BufRead as _,
    os::unix::ffi::OsStrExt as _,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, anyhow, bail};
use clap::Parser;
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

    /// Treat `name` as the module name instead of resolving it as an alias.
    #[clap(long, default_value = "false")]
    module_name: bool,
}

fn main() -> anyhow::Result<()> {
    let Args {
        quiet,
        name,
        module_name,
    } = Parser::parse();
    let ret = try_main(quiet, name, module_name);
    if quiet { Ok(()) } else { ret }
}

fn try_main(quiet: bool, name: String, module_name: bool) -> anyhow::Result<()> {
    let modules_dir = resolve_modules_dir()?;

    let module = if module_name {
        name
    } else {
        output!(quiet, "resolving alias for module: {}", name);
        resolve_alias(quiet, &modules_dir, &name)?
    };

    let module_path = find_module_path(&modules_dir, &module)?;

    output!(quiet, "loading module: {}", module_path.display());

    let modules_dep_path = modules_dir.join("modules.dep");
    let modules_dep_path = match File::open(&modules_dep_path) {
        Ok(_) => Some(modules_dep_path),
        Err(err) if module_name && err.kind() == std::io::ErrorKind::NotFound => {
            output!(
                quiet,
                "{} not found; loading module without dependency metadata",
                modules_dep_path.display()
            );
            None
        }
        Err(err) => {
            return Err(err).with_context(|| format!("open(): {}", modules_dep_path.display()));
        }
    };

    let mut loaded = HashSet::<PathBuf>::new();
    load_module_with_deps(
        &modules_dir,
        modules_dep_path.as_deref(),
        &module_path,
        &mut loaded,
    )?;
    output!(quiet, "module loaded successfully");
    Ok(())
}

fn find_module_path(modules_dir: &Path, module: &str) -> anyhow::Result<PathBuf> {
    find_module_path_impl(&modules_dir.join("kernel"), OsStr::new(module))?
        .ok_or_else(|| anyhow!("module not found: {}", module))
}

fn find_module_path_impl(dir: &Path, module: &OsStr) -> anyhow::Result<Option<PathBuf>> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read_dir({})", dir.display()))? {
        let entry = entry.with_context(|| format!("read_dir({})", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("file_type({})", path.display()))?;
        if file_type.is_dir() {
            if let Some(path) = find_module_path_impl(&path, module)? {
                return Ok(Some(path));
            }
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if matches_module_file(&path, module) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn matches_module_file(path: &Path, module: &OsStr) -> bool {
    match path.extension() {
        Some(ext) if ext == "ko" => path.file_stem() == Some(module),
        Some(ext) if ext == "xz" => {
            let Some(stem) = path.file_stem() else {
                return false;
            };
            let stem = Path::new(stem);
            stem.extension() == Some(OsStr::new("ko")) && stem.file_stem() == Some(module)
        }
        _ => false,
    }
}

fn load_module_with_deps(
    modules_dir: &Path,
    modules_dep_path: Option<&Path>,
    module_path: &Path,
    loaded: &mut HashSet<PathBuf>,
) -> anyhow::Result<()> {
    let rel = module_path
        .strip_prefix(modules_dir)
        .with_context(|| {
            format!(
                "failed to strip prefix {} from {}",
                modules_dir.display(),
                module_path.display()
            )
        })?
        .to_path_buf();
    if !loaded.insert(rel.clone()) {
        return Ok(());
    }

    if let Some(modules_dep_path) = modules_dep_path {
        let deps = resolve_deps(modules_dep_path, &rel)?;
        for dep in deps {
            load_module_with_deps(
                modules_dir,
                Some(modules_dep_path),
                &modules_dir.join(dep),
                loaded,
            )?;
        }
    }

    let extension = module_path
        .extension()
        .ok_or_else(|| anyhow!("module has no extension: {}", module_path.display()))?;

    let contents = read_to_end(&module_path, extension == "xz")
        .with_context(|| format!("read_to_end({})", module_path.display()))?;

    if !contents.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
        bail!("module is not an valid ELF file");
    }

    match init_module(&contents, c"") {
        Ok(()) => Ok(()),
        Err(e) => {
            if e == nix::errno::Errno::EEXIST {
                Err(anyhow!("module already loaded"))
            } else {
                Err(anyhow!("failed to load module: {}", e))
            }
        }
    }
}

fn resolve_deps(modules_dep_path: &Path, module_rel: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let modules_dep = File::open(modules_dep_path)
        .with_context(|| format!("open(): {}", modules_dep_path.display()))?;
    let mut modules_dep_reader = std::io::BufReader::new(modules_dep);
    let mut line = Vec::new();
    let module_rel = module_rel.as_os_str().as_bytes();
    loop {
        line.clear();
        if modules_dep_reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        while line
            .last()
            .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
        {
            let _ = line.pop();
        }
        let Some(i) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        if &line[..i] != module_rel {
            continue;
        }
        let deps = line[i + 1..]
            .split(|byte| matches!(byte, b' ' | b'\t'))
            .filter(|dep| !dep.is_empty())
            .map(|dep| PathBuf::from(OsStr::from_bytes(dep)))
            .collect();
        return Ok(deps);
    }
    Ok(Vec::new())
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
                .with_context(|| format!("alias line missing alias: {line}"))?;
            let module = parts
                .next()
                .with_context(|| format!("alias line missing module: {line}"))?;
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
