"""Python lint and type-check tests using rules_lint's pinned tools."""

load("@aspect_rules_lint//lint:lint_test.bzl", "lint_test")
load("@aspect_rules_lint//lint:ruff.bzl", "lint_ruff_aspect")
load("@aspect_rules_lint//lint:ty.bzl", "lint_ty_aspect")

ruff = lint_ruff_aspect(
    binary = Label("@aspect_rules_lint//lint:ruff_bin"),
    configs = [Label("//:pyproject.toml")],
)

ty = lint_ty_aspect(
    binary = Label("@aspect_rules_lint//lint:ty_bin"),
    config = Label("//:pyproject.toml"),
)

ruff_test = lint_test(aspect = ruff)
ty_test = lint_test(aspect = ty)
