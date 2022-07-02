use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};

mod tests;
use tests::IntegrationTest;

fn main() -> anyhow::Result<()> {
    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // Run the tests
    for t in inventory::iter::<IntegrationTest> {
        info!("Running {}", t.name);
        if let Err(e) = (t.test_fn)() {
            panic!("{}", e)
        }
    }

    Ok(())
}
