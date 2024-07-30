use std::{path::PathBuf, process::exit};

use aya_tool::btf::print_btf;
use aya_tool::generate::{generate, InputFile};
use clap::Parser;

#[derive(Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    /// Generate Rust bindings to Kernel types using bpftool
    #[clap(name = "generate", action)]
    Generate {
        #[clap(long, default_value = "/sys/kernel/btf/vmlinux", action)]
        btf: PathBuf,
        #[clap(long, conflicts_with = "btf", action)]
        header: Option<PathBuf>,
        #[clap(action)]
        names: Vec<String>,
        #[clap(last = true, action)]
        bindgen_args: Vec<String>,
    },
    /// Pretty print an ELF file's BTF
    #[clap(name = "print-btf", action)]
    PrintBtf {
        /// The ELF file to print BTF for
        target: PathBuf,
    },
}

fn main() {
    if let Err(e) = try_main() {
        eprintln!("{e:#}");
        exit(1);
    }
}

fn try_main() -> Result<(), anyhow::Error> {
    let opts = Options::parse();
    match opts.command {
        Command::Generate {
            btf,
            header,
            names,
            bindgen_args,
        } => {
            let bindings: String = if let Some(header) = header {
                generate(InputFile::Header(header), &names, &bindgen_args)?
            } else {
                generate(InputFile::Btf(btf), &names, &bindgen_args)?
            };
            println!("{bindings}");
        }
        Command::PrintBtf { target } => {
            print_btf(target)?;
        }
    };

    Ok(())
}
