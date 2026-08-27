# AGENTS NOTES

- Repository: aya (Rust library and tooling for working with eBPF programs).
- Development tooling:
  - Public API changes must include the corresponding `xtask/public-api/*.txt`
    fixture updates in the same PR; do not edit the fixtures by hand. Regenerate
    for Linux x86-64 GNU:

    ```sh
    cargo +nightly xtask public-api --bless --target x86_64-unknown-linux-gnu
    ```

  - Many crates only build on Linux; on macOS lint and type check using

  ```sh
  cargo xtask clippy -- --target x86_64-unknown-linux-musl
  ```

- Coding guidelines:
  - Use github or bootlin permalinks when referencing kernel sources.
- Testing (if local machine is not Linux):

  ```sh
  cargo xtask integration-test vm \
    --cache-dir test/.tmp --kernel-arch <arch> [VERSIONS]... \
    -- <test-filter> [ARGS]...
  ```
