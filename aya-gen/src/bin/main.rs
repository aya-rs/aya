use aya_gen::btf_types;

use std::{path::PathBuf, process::exit};

use structopt::StructOpt;
#[derive(StructOpt)]
pub struct Options {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt)]
enum Command {
    #[structopt(name = "btf-types")]
    BtfTypes {
        #[structopt(long, default_value = "/sys/kernel/btf/vmlinux")]
        btf: PathBuf,
        #[structopt(long)]
        probe_read_getters: bool,
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
    let opts = Options::from_args();
    match opts.command {
        Command::BtfTypes {
            btf,
            probe_read_getters,
            names,
        } => {
            let bindings = btf_types::generate(&btf, &names, probe_read_getters)?;
            println!("{}", bindings);
        }
    };

    Ok(())
}
