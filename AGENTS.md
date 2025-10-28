# AGENTS NOTES

- Repository: aya (Rust library and tooling for working with eBPF programs).
- Development tooling:
  - Do not regenerate public API fixtures; the user handles that.
  - Many crates only build on Linux; on macOS lint and type check using

  ```sh
  ./clippy.sh --target x86_64-unknown-linux-musl
  ```

- Coding guidelines:
  - Use github or bootlin permalinks when referencing kernel sources.
- Integration testing:
  - Prepare:

    ```sh
    .github/scripts/download_kernel_images.sh \
      test/.tmp/debian-kernels/<arch> <arch> [VERSIONS]...
    ```

  - Run:

    <!-- markdownlint-disable line-length -->

    ```sh
    find test/.tmp -name '*.deb' -print0 | xargs -0 -t sh -c \
      'cargo xtask integration-test vm --cache-dir test/.tmp "$@" -- <test-filter> [ARGS]...' _
    ```

    <!-- markdownlint-restore -->
