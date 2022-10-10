use log::info;

mod tests;
use tests::IntegrationTest;

use clap::Parser;
#[derive(Debug, Parser)]
pub struct RunOptions {
    #[clap(short, long, value_parser)]
    tests: Option<Vec<String>>,
}

#[derive(Debug, Parser)]
struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    /// Run one or more tests: ... -- run -t test1 -t test2
    Run(RunOptions),
    /// List all the tests: ... -- list
    List
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cmd = Command::parse();

    match cmd {
        Command::Run(opts) => {
            match opts.tests {
                Some(tests) => {
                    for t in inventory::iter::<IntegrationTest> {
                        if tests.contains(&t.name.into()) {
                            info!("Running {}", t.name);
                            if let Err(e) = (t.test_fn)() {
                                panic!("{}", e)
                            }
                        }
                    }
                }
                None => {
                    for t in inventory::iter::<IntegrationTest> {
                        info!("Running {}", t.name);
                        if let Err(e) = (t.test_fn)() {
                            panic!("{}", e)
                        }
                    }
                }
            }
        }
        Command::List => {
            for t in inventory::iter::<IntegrationTest> {
                info!("{}", t.name);
            }
        }
    }

    Ok(())
}
