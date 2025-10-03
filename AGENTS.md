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

    find test/.tmp -name '*.deb' -print0 | xargs -t -0 -I {} \
      sh -c "dpkg --fsys-tarfile {} | tar -C test/.tmp \
        --wildcards --extract '**/boot/*' '**/modules/*' --file -"
    ```

    You might need to use gtar rather than tar on mac.
  - Run:

    <!-- markdownlint-disable line-length -->

    ```sh
    .github/scripts/find_kernels.py | xargs -0 -t sh -c \
      'cargo xtask integration-test vm --cache-dir test/.tmp "$@" -- <test-filter> [ARGS]...' _
    ```

    <!-- markdownlint-restore -->
