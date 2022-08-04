use log::info;

mod tests;
use tests::IntegrationTest;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Run the tests
    for t in inventory::iter::<IntegrationTest> {
        info!("Running {}", t.name);
        if let Err(e) = (t.test_fn)() {
            panic!("{}", e)
        }
    }

    Ok(())
}
