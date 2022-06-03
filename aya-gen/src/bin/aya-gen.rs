use aya_gen::btf_types;

use std::{path::PathBuf, process::exit};

use clap::Parser;

#[derive(Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    #[clap(name = "btf-types")]
    BtfTypes {
        #[clap(long, default_value = "/sys/kernel/btf/vmlinux")]
        btf: PathBuf,
        names: Vec<String>,
    },
}

fn main() {
    if let Err(e) = try_main() {
        eprintln!("{:#}", e);
        exit(1);
    }
}

fn try_main() -> Result<(), anyhow::Error> {
    let opts = Options::parse();
    match opts.command {
        Command::BtfTypes { btf, names } => {
            let bindings = btf_types::generate(&btf, &names)?;
            println!("{}", bindings);
        }
    };

    Ok(())
}
