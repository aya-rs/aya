# Releasing the aya project

This document describes the process of releasing the aya project.

## Release process

### 0. Who can release?

Only members of [aya-rs/owners][owners-team] have the permissions to:

- Push packages to crates.io
- Make the necessary changes in GitHub to create a release

### 1. cargo smart-release

This project uses [cargo-smart-release] to automate the release process. The
following commands *should* be sufficient to release the project:

> [!IMPORTANT]
> The `--execute` flag is used to actually perform the release.
> Remove it to do a dry-run first.
>
> The `--no-changelog-github-release` flag is used to prevent creating a GitHub
> release with the changelog. This is required since it will fail to find the
> tags unless they've been pushed.

```sh
cargo smart-release aya --execute --signoff --no-changelog-github-release
cargo smart-release aya-ebpf --execute --signoff--no-changelog-github-release
cargo smart-release aya-log-ebpf --execute --signoff --no-changelog-github-release
cargo smart-release aya-log --execute  --signoff--no-changelog-github-release
```

### 2. Push the commits and tags

This assumes you opted to disable branch protection:

```sh
git push origin main
git push origin tag aya-vX.Y.Z
git push origin tag aya-ebpf-vX.Y.Z
# etc...
```

> [!WARNING]
> Remember to re-enable branch protection after pushing the commits/tags.

Opening PRs for the changes made by the release would be a good enhancement in
future releases. However we also need to create the tags via GitHub action due
to branch protection.

### 3. Create a GitHub release

Create a GitHub release for each crate with the changelog entries for the new
version. The changelog entries are in the `CHANGELOG.md` file in each crate's
root directory.

The easiest way to do this is via the `gh` CLI:

```sh
VERSION=1.2.3
NOTES="$(awk -v v=$VERSION '
  BEGIN {RS=""; FS="\n"}
  $0 ~ "## " v {
    print $0
    s=1
    next
  }
  s && /^## / {
    exit
  }
  s {
    print $0
    print ""
  }
' aya/CHANGELOG.md)"
gh release create aya-v$VERSION --title "aya v$VERSION" --notes "$NOTES"
```

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
