//! modprobe is used to load kernel modules into the kernel.
//!
//! This implementation is incredibly naive and is only designed to work within
//! the constraints of the test environment. Not for production use.

use std::{
    ffi::CString,
    io::{BufRead as _, Read as _},
    path::Path,
};

use clap::Parser;
use glob::glob;
use nix::kmod::init_module;
use test_distro::resolve_modules_dir;

macro_rules! exit_with_error {
    ($quiet:expr, $($arg:tt)*) => {
        if !$quiet {
            eprintln!($($arg)*);
            std::process::exit(1);
        } else {
            std::process::exit(0);
        }
    };
}

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

fn main() {
    let Args { quiet, name } = Parser::parse();

    let mut module = name.to_string();

    let modules_dir = match resolve_modules_dir() {
        Ok(modules_dir) => modules_dir,
        Err(e) => {
            exit_with_error!(quiet, "Failed to resolve modules dir: {}", e);
        }
    };

    output!(quiet, "resolving alias for module: {}", module);
    module = resolve_alias(quiet, &modules_dir, &module);

    let pattern = format!("{}/kernel/**/{}.ko*", modules_dir.to_string_lossy(), module);
    let module_path = if let Some(path) = glob(&pattern)
        .expect("Failed to read glob pattern")
        .filter_map(Result::ok)
        .next()
    {
        path
    } else {
        exit_with_error!(quiet, "Module not found: {}", module);
    };

    output!(quiet, "Loading module: {}", module_path.display());
    let mut f = match std::fs::File::open(&module_path) {
        Ok(f) => f,
        Err(e) => {
            exit_with_error!(quiet, "Failed to open module: {}", e);
        }
    };
    let stat = f.metadata().expect("Failed to get metadata");

    let extension = module_path
        .as_path()
        .extension()
        .expect("Failed to get file extension");
    let contents = if extension == "xz" {
        output!(quiet, "Decompressing module");
        let mut decompressed = Vec::with_capacity(stat.len() as usize * 2);
        if let Err(e) = xz2::read::XzDecoder::new(f).read_to_end(&mut decompressed) {
            exit_with_error!(quiet, "Failed to decompress module: {}", e);
        }
        decompressed
    } else {
        let mut contents: Vec<u8> = Vec::with_capacity(stat.len() as usize);
        f.read_to_end(&mut contents).expect("read");
        contents
    };

    if contents[0..4] != [0x7f, 0x45, 0x4c, 0x46] {
        exit_with_error!(quiet, "Module is not an valid ELF file");
    }

    let res = init_module(&contents, &CString::new("").unwrap());
    if let Err(e) = res {
        if e == nix::errno::Errno::EEXIST {
            exit_with_error!(quiet, "Module already loaded");
        }
        exit_with_error!(quiet, "Failed to load module: {}", e);
    }
    output!(quiet, "Module loaded successfully");
}

fn resolve_alias(quiet: bool, module_dir: &Path, name: &str) -> String {
    let modules_alias = module_dir.join("modules.alias");
    output!(
        quiet,
        "opening modules.alias file: {}",
        modules_alias.display()
    );
    let alias_file = match std::fs::File::open(modules_alias) {
        Ok(alias_file) => alias_file,
        Err(e) => {
            exit_with_error!(quiet, "Failed to open modules.alias file: {}", e);
        }
    };
    let alias_file = std::io::BufReader::new(alias_file);

    for line in alias_file.lines() {
        let line = line.expect("read line");
        if line.starts_with("alias ") {
            let mut parts = line.split_whitespace();
            let _ = parts.next(); // skip "alias "
            let alias = parts.next().expect("no alias");
            let module = parts.next().expect("no module");
            if alias == name {
                return module.to_string();
            }
        }
    }

    name.to_string()
}
