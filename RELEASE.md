# Releasing the aya project

This document describes the process of releasing the aya project.

## Release process

### 0. Who can release?

Only members of [aya-rs/owners][owners-team] have the permissions to:

- Push packages to crates.io
- Make the necessary changes in GitHub to create a release

### 1. Create a release branch and run cargo smart-release

This project uses [cargo-smart-release] to automate the release process. Start
from the default branch, create a fresh release branch, and run the command
below on that branch. As soon as the command succeeds it will publish each crate
and push the branch plus tags to the remote automatically, so double-check that
everything is ready before invoking
it.

> [!IMPORTANT]
> The `--execute` flag is used to actually perform the release.
> Remove it to do a dry-run first.

```sh
git checkout -b my-release-branch
cargo smart-release \
  aya \
  aya-ebpf \
  aya-log-ebpf \
  aya-log \
  --execute \
  --no-changelog-github-release \
  --signoff
```

### 2. Open a pull request

Because the release branch gets pushed automatically on success, open a PR
against the default branch and merge it once everything looks good. This keeps
git history auditable even though crates.io already has the freshly published
artifacts.

> [!IMPORTANT]
> Use a fast-forward merge to ensure the tags are reachable from the default
> branch.

## Release Debugging

Sometimes the release process can fail.

Here are some common issues and how to fix them:

### `cargo smart-release` doesn't compute the correct version

You can manually specify the version to release by passing the `--bump` flag
and specifying either `major`, `minor`, or `patch`. This *should* be computed
from the commits in the changelog, but sometimes it doesn't work as expected.

### WOULD stop release after commit as the changelog entry is empty for crate

If you see the message ☝ in the output of `cargo smart-release`, it means that
the generated changelog entry for the crate is empty. This can happen if, for
example, the only change is a dependency update. In this case, you can manually
edit the changelog entry in the crate's `CHANGELOG.md` file to include a note
about the dependency update under the `## Unreleased` section.
[c3f0c7dc] is an example of such a commit.

[cargo-smart-release]: https://github.com/Byron/cargo-smart-release
[owners-team]: https://github.com/orgs/aya-rs/teams/owners
[c3f0c7dc]: https://github.com/aya-rs/aya/commit/c3f0c7dc3fb285da091454426eeda0723389f0f1
