use libtest_mimic::{Arguments, Trial};

mod tests;
use tests::IntegrationTest;

fn main() {
    env_logger::init();
    let mut args = Arguments::from_args();
    // Force to run single-threaded
    args.test_threads = Some(1);
    let tests = inventory::iter::<IntegrationTest>
        .into_iter()
        .map(|test| {
            Trial::test(test.name, move || {
                (test.test_fn)();
                Ok(())
            })
        })
        .collect();
    libtest_mimic::run(&args, tests).exit();
}
