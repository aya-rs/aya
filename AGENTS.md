# AGENTS NOTES

- Repository: aya (Rust library and tooling for working with eBPF programs).
- Development tooling:
  - Do not regenerate public API fixtures; the user handles that.
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
