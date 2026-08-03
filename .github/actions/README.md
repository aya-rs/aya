# Reusable nightly updates

`../workflows/nightly-update.yml` runs at 03:00 UTC, by manual dispatch, or
when another repository calls it. Its only input is `updater-script`. Each
repository keeps one update pull request on
`create-pull-request/rust-nightly`.

## Standalone updaters

`python3 scripts/update-rust-nightly.py` prints Aya's committed nightly pin.
Adding `latest` prints JSON containing `nightly` and `rust_commit`. Adding
`update` advances `MODULE.bazel`, regenerates `MODULE.bazel.lock` with
`bazel mod deps --lockfile_mode=update`, and prints the updated pin.

bpf-linker's `scripts/update-rustc-llvm.py` owns its LLVM selection and
verification. Its `RUST_NIGHTLY_UPDATER` environment variable points to Aya's
standalone executable, whose `latest` command supplies the nightly and rustc
commit.

`update-nightly/action.yml` sets that path to the Aya executable at the
provider's pinned revision and runs the caller's updater. Each repository
keeps its own nightly pin and update policy.

## Safe publication

The update job runs only on the caller's default branch and limits the pull
request to `MODULE.bazel` and `MODULE.bazel.lock`. Upstream repositories use
`CRABBY_GITHUB_TOKEN` from their branch-restricted `nightly-promotion`
environment to create the pull request and enable native auto-merge.

Strict required checks validate the current base before GitHub merges the
update. A failing nightly stays on its pull request. Forks without a Crabby
token use their writable `GITHUB_TOKEN`; their CI and merge require manual
approval.

External callers must pin the reusable workflow to a full Aya commit SHA.
