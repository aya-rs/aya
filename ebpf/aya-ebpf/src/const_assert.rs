pub(crate) struct Assert<const COND: bool> {}

pub(crate) trait IsTrue {}

impl IsTrue for Assert<true> {}
