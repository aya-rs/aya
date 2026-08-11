#[derive(Debug)]
pub struct Errors<E>(Vec<E>);

impl<E> Errors<E> {
    pub const fn new(errors: Vec<E>) -> Self {
        Self(errors)
    }
}

impl<E> std::fmt::Display for Errors<E>
where
    E: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(errors) = self;
        for (i, error) in errors.iter().enumerate() {
            if i != 0 {
                writeln!(f)?;
            }
            #[expect(
                clippy::use_debug,
                reason = "<anyhow::Error as Display> does not show backtrace"
            )]
            write!(f, "{error:?}")?;
        }
        Ok(())
    }
}

impl<E> std::error::Error for Errors<E> where E: std::fmt::Debug {}
