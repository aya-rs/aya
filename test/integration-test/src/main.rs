use log::info;

mod tests;
use tests::IntegrationTest;

use clap::Parser;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
pub struct RunOptions {
    #[clap(short, long, value_parser)]
    tests: Option<Vec<String>>,
}

#[derive(Debug, Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Parser)]
enum Command {
    /// Run one or more tests: ... -- run -t test1 -t test2
    Run(RunOptions),
    /// List all the tests: ... -- list
    List,
}

macro_rules! exec_test {
    ($test:expr) => {{
        info!("Running {}", $test.name);
        ($test.test_fn)();
    }};
}

macro_rules! exec_all_tests {
    () => {{
        for t in inventory::iter::<IntegrationTest> {
            exec_test!(t)
        }
    }};
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match &cli.command {
        Some(Command::Run(opts)) => match &opts.tests {
            Some(tests) => {
                for t in inventory::iter::<IntegrationTest> {
                    if tests.contains(&t.name.into()) {
                        exec_test!(t)
                    }
                }
            }
            None => {
                exec_all_tests!()
            }
        },
        Some(Command::List) => {
            for t in inventory::iter::<IntegrationTest> {
                info!("{}", t.name);
            }
        }
        None => {
            exec_all_tests!()
        }
    }

    Ok(())
}
