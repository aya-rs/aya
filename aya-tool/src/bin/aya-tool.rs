#![expect(unused_crate_dependencies, reason = "used in lib")]

use std::path::PathBuf;

use aya_tool::generate::{InputFile, generate};
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
}

fn main() -> Result<(), anyhow::Error> {
    use std::io::Write as _;

    let Options { command } = Parser::parse();
    let bindings = match command {
        Command::Generate {
            btf,
            header,
            names,
            bindgen_args,
        } => {
            if let Some(header) = header {
                generate(InputFile::Header(header), &names, &bindgen_args)
            } else {
                generate(InputFile::Btf(btf), &names, &bindgen_args)
            }
        }
    }?;
    std::io::stdout().write_all(bindings.as_bytes())?;
    Ok(())
}
