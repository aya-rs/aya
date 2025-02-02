//! modprobe is used to load kernel modules into the kernel.
//!
//! This implementation is incredibly naive and is only designed to work within
//! the constraints of the test environment. Not for production use.

use std::{
    ffi::CString,
    io::Read as _,
    io::Write as _,
    path::{Path, PathBuf},
};

use clap::Parser;
use glob::glob;
use nix::{kmod::init_module, sys::utsname::uname};

macro_rules! exit_with_error {
    ($quiet:expr, $($arg:tt)*) => {
        if !$quiet {
            eprintln!($($arg)*);
            std::process::exit(1);
        } else {
            let mut log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/modprobe.log")
                .expect("Failed to open log file");
            writeln!(log_file, $($arg)*).expect("Failed to write to log file");
            log_file.flush().expect("Failed to flush log file");
            std::process::exit(0);
        }
    };
}

macro_rules! output {
    ($quiet:expr, $($arg:tt)*) => {
        if !$quiet {
            println!($($arg)*);
        } else {
            let mut log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/modprobe.log")
                .expect("Failed to open log file");
            writeln!(log_file, $($arg)*).expect("Failed to write to log file");
            log_file.flush().expect("Failed to flush log file");
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
    let args = Args::parse();

    let module = &args.name;

    // Modules are in `/lib/modules/kernel` or `/lib/modules/$(uname -r)/kernel`

    let mut modules_dir = PathBuf::from("/lib/modules");

    if !modules_dir.join("kernel").exists() {
        let utsname = uname().expect("Failed to get uname");
        let release = utsname.release();
        if modules_dir.join(release).exists() {
            modules_dir = modules_dir.join(release);
        } else {
            exit_with_error!(
                args.quiet,
                "No kernel modules found for release: {}",
                release.to_string_lossy()
            );
        }
    }
    modules_dir = modules_dir.join("kernel");

    // First, attempt to find the module via an alias.

    let mut module_path = search_module(&modules_dir, module.to_string());

    if module_path.is_none() {
        let pattern = format!("{}/**/{}.ko*", modules_dir.to_string_lossy(), module);
        let m = glob(&pattern)
            .expect("Failed to read glob pattern")
            .filter_map(Result::ok)
            .next();
        if m.is_some() {
            module_path = Some(m.unwrap());
        }
    }

    if module_path.is_none() {
        exit_with_error!(args.quiet, "Module not found: {}", module);
    }

    let module_path = module_path.unwrap();

    output!(args.quiet, "Loading module: {}", module_path.display());
    let mut f = std::fs::File::open(module_path.clone()).expect("Failed to open module file");
    let mut contents: Vec<u8> = Vec::new();
    f.read_to_end(&mut contents).unwrap();

    if let Some(extension) = module_path.as_path().extension() {
        if extension == "xz" {
            output!(args.quiet, "Decompressing module");
            let mut decompressed = Vec::new();
            xz2::read::XzDecoder::new(&contents[..])
                .read_to_end(&mut decompressed)
                .expect("Failed to decompress module");
            contents = decompressed;
        }
    }

    if contents[0..4] != [0x7f, 0x45, 0x4c, 0x46] {
        exit_with_error!(args.quiet, "Module is not an valid ELF file");
    }

    let res = init_module(&contents, &CString::new("").unwrap());
    if let Err(e) = res {
        if e == nix::errno::Errno::EEXIST {
            exit_with_error!(args.quiet, "Module already loaded");
        }
        exit_with_error!(args.quiet, "Failed to load module: {}", e);
    }
    output!(args.quiet, "Module loaded successfully");
}

fn search_module(search_path: &Path, module: String) -> Option<PathBuf> {
    // 1. Convert hyphens to underscores

    let module = module.replace("-", "_");

    // 2. Split on underscores

    let parts = module.split("_").collect::<Vec<_>>();

    // 3. Iterate over parts.
    // When no directory is found, the remaining parts are the module name.
    // Check if a file exists with the module name (with .ko or .ko.xz extension)

    let mut search_path = search_path.to_path_buf();
    for i in 0..parts.len() {
        // Starting from the module base path, check if a directory exists.
        // If it does, append the part to the path and continue.
        if search_path.join(parts[i]).exists() {
            search_path = search_path.join(parts[i]);
            continue;
        }
        // If the directory doesn't exist, the remaining parts are the module name.
        let module = parts[i..].join("_");

        search_path = search_path.join(module);

        let m = glob(&format!("{}.ko*", search_path.to_string_lossy()))
            .expect("Failed to read glob pattern")
            .filter_map(Result::ok)
            .next();

        return m;
    }
    None
}
