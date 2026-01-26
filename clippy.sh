#!/usr/bin/env sh

set -eux

# macOS cross-compilation fixes for libbpf-sys vendored dependencies:
# - zlib: configure sets AR=libtool on Darwin (Mach-O format, not ELF)
#   → make wrapper overrides AR/RANLIB (https://github.com/madler/zlib/issues/331)
# - elfutils: configure needs AR/RANLIB in environment to find cross tools
# - Autoconf cache variables to skip checks that fail during cross-compilation
#   (https://github.com/libbpf/libbpf-sys/issues/137)
if [ "$(uname -s)" = "Darwin" ]; then
  tmp_bin=$(mktemp -d)
  cat > "$tmp_bin/make" << 'EOF'
#!/bin/bash
exec /usr/bin/make AR=x86_64-linux-musl-ar ARFLAGS=rcs RANLIB=x86_64-linux-musl-ranlib "$@"
EOF
  chmod +x "$tmp_bin/make"
  export PATH="$tmp_bin:$PATH"
  export AR=x86_64-linux-musl-ar
  export RANLIB=x86_64-linux-musl-ranlib
  export ac_cv_search_argp_parse='none required'
  export ac_cv_search__obstack_free='none required'
  export ac_cv_search_gzdirect='none required'
  export ac_cv_search_fts_close='none required'
fi

# `-C panic=abort` because "unwinding panics are not supported without std"; integration-ebpf
# contains `#[no_std]` binaries.
#
# `-Zpanic_abort_tests` because "building tests with panic=abort is not supported without
# `-Zpanic_abort_tests`"; Cargo does this automatically when panic=abort is set via profile but we
# want to preserve unwinding at runtime - here we are just running clippy so we don't care about
# unwinding behavior.
#
# `+nightly` because "the option `Z` is only accepted on the nightly compiler".
cargo +nightly hack clippy "$@" \
  --all-targets \
  --feature-powerset \
  -- --deny warnings \
  -C panic=abort \
  -Zpanic_abort_tests

export CLIPPY_ARGS='--deny=warnings'
export RUSTDOCFLAGS='--no-run -Z unstable-options --test-builder clippy-driver'

cargo +nightly hack test --doc "$@" --feature-powerset

for arch in aarch64 arm loongarch64 mips powerpc64 riscv64 s390x x86_64; do
  export RUSTFLAGS="--cfg bpf_target_arch=\"$arch\""

  for target in bpfeb-unknown-none bpfel-unknown-none; do
    cargo +nightly hack clippy \
      --target "$target" \
      -Zbuild-std=core \
      --package aya-ebpf \
      --package aya-ebpf-bindings \
      --package aya-log-ebpf \
      --package integration-ebpf \
      --feature-powerset \
      -- --deny warnings
  done

  RUSTDOCFLAGS="$RUSTDOCFLAGS $RUSTFLAGS" cargo +nightly hack test --doc "$@" \
    --package aya-ebpf \
    --package aya-ebpf-bindings \
    --package aya-log-ebpf \
    --package integration-ebpf \
    --feature-powerset
done
