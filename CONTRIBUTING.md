# Contributing Guide

* [New Contributor Guide](#contributing-guide)
  * [Ways to Contribute](#ways-to-contribute)
  * [Find an Issue](#find-an-issue)
  * [Ask for Help](#ask-for-help)
  * [Pull Request Lifecycle](#pull-request-lifecycle)
  * [Logical Grouping of Commits](#logical-grouping-of-commits)
  * [Commit message guidelines](#commit-message-guidelines)
  * [Pull Request Checklist](#pull-request-checklist)
  * [Testing Expectations](#testing-expectations)
  * [Workflow Dependencies](#workflow-dependencies)
  * [Source References](#source-references)
  * [Documentation Style](#documentation-style)

Welcome! We are glad that you want to contribute to our project! 💖

As you get started, you are in the best position to give us feedback on areas of
our project that we need help with including:

* Problems found during setting up a new developer environment
* Gaps in our Quickstart Guide or documentation
* Bugs in our automation scripts

If anything doesn't make sense, or doesn't work when you run it, please open a
bug report and let us know!

## Ways to Contribute

We welcome many different types of contributions including:

* New features
* Builds, CI/CD
* Bug fixes
* Documentation
* Issue Triage
* Answering questions on [Discord]
* Web design
* Communications / Social Media / Blog Posts
* Release management
* Community management

Not everything happens through a GitHub pull request. Please come to our
[Discord] and let's discuss how we can work together.

## Find an Issue

Issues labelled as ["good first issue"] are suitable for new
contributors. They provide extra information to help you make your first
contribution.

Issues labelled as ["help wanted"] are usually more difficult. We
recommend them for people who aren't core maintainers, but have either made some
contributions already or feel comfortable with starting from more demanding
tasks.

Sometimes there won’t be any issues with these labels. That’s ok! There is
likely still something for you to work on. If you want to contribute but you
don’t know where to start or can't find a suitable issue, you can reach out to
us on [Discord] and we will be happy to help.

Once you see an issue that you'd like to work on, please post a comment saying
that you want to work on it. Something like "I want to work on this" is fine.

## Ask for Help

The best way to reach us with a question when contributing is to ask on:

* The original GitHub issue
* Our [Discord]

## Pull Request Lifecycle

Pull requests are managed by Mergify.

Our process is currently as follows:

1. When you open a PR a maintainer will automatically be assigned for review
1. Make sure that your PR is passing CI - if you need help with failing checks
   please feel free to ask!
1. Once it is passing all CI checks, a maintainer will review your PR and you
   may be asked to make changes.
1. When you have received an approval from at least one maintainer, your PR will
   be merged.

In some cases, other changes may conflict with your PR. If this happens, you
will get notified by a comment in the issue that your PR requires a rebase, and
the `needs-rebase` label will be applied. Once a rebase has been performed, this
label will be automatically removed.

## Logical Grouping of Commits

Prefer small, focused pull requests that can be reviewed and merged independently.
Split changes that do not depend on one another into separate PRs.

Keep each commit focused on one logical change. For work with multiple distinct
steps, prefer an ordered series of reviewable commits, with prerequisites before
the changes that use them. A simple change can remain a single commit. Each
commit should build, pass the tests relevant to its change, and pass the public
API check (`cargo xtask public-api --target x86_64-unknown-linux-gnu`). Use this
target to match the checked-in fixtures. Do not rely on a later commit to make
an earlier one work.

Include tests for a behavior change or bug fix in the commit that introduces it,
together with any required caller and documentation updates. Separate test
commits can be useful for shared test infrastructure, coverage of existing
behavior, or a review split with a clear reason.

Present API changes in their intended final form in the submitted series. When
a new API's name, signature, or ownership model changes during review, revise
earlier commits rather than leaving temporary designs in the series. If this is
difficult, split the work into smaller PRs with clear, stable API boundaries.
Retain staged migrations of existing APIs only when each step has a clear
compatibility or review benefit.

Before requesting review, use an interactive rebase to organize checkpoint
commits into logical changes. Fold subsequent review fixes into the relevant
commits rather than adding commits such as "Fix review comments".

## Commit message guidelines

A good commit message should describe what changed and why. Keep relevant
context in the commit message itself, rather than only in the PR description.

See [How to Write a Git Commit Message](https://cbea.ms/git-commit/) for
background. The Aya-specific rules below take precedence; unlike the article,
Aya uses lowercase subjects.

1. The first line must:
    * Briefly describe the change in at most 50 characters, including the prefix
    * Be entirely in lowercase with the exception of proper nouns, acronyms, and
      the words that refer to code, like function/variable names
    * Be prefixed with the name of the affected crate or area, followed by a
      colon and a space

    Examples:
    * `aya: handle reordered functions`
    * `aya-bpf: SkSkbContext: add ::l3_csum_replace`

1. Keep the second line blank.
1. Keep each body line at or below 72 columns (except for long URLs).
1. If your patch fully resolves an open issue, you can add an issue-closing
   reference at the end of the commit message. Use `Fixes #1337.` or
   `Closes #1337.` for closing references, and `Refs #1234.` for related issues
   that are not fully resolved. Omit the colon and end each reference with a
   period. Multiple related issues may be listed together, separated by commas.

   Examples:

   * `Fixes #1337.`
   * `Closes #1337.`
   * `Refs #1234.`

Sample complete commit message:

```txt
subcrate: explain the commit in one line

Body of commit message is a few lines of text, explaining things
in more detail, possibly giving some background about the issue
being fixed, etc.

The body of the commit message can be several paragraphs, and
please do proper word-wrap and keep columns shorter than about
72 characters or so. That way, `git log` will show things
nicely even when it is indented.

Fixes #1337.
Refs #453, #154.
```

## Pull Request Checklist

When you submit your pull request, or you push new commits to it, our automated
systems will run some checks on your new code. We require that your pull request
passes these checks, but we also have more criteria than just that before we can
accept and merge it. Theses requirements are described in the
[Pull Request Template].

## Testing Expectations

Tests should exercise observable Aya behavior and fail for plausible broken
implementations. For a bug fix, prefer a regression test that distinguishes the
fix from the previous behavior. Test shared behavior in the module that owns it;
add caller-specific cases when they cover a distinct contract or failure mode.

Use unit tests for local contracts, such as argument translation or error
mapping. When the claim depends on kernel behavior, use integration coverage
that observes the result, such as program execution or actual resource cleanup.
A mock that checks parameters or call order alone does not establish that the
kernel operation worked.

Cover defined behavior for both supported and unsupported features. When an API
specifies the unsupported result, assert that result instead of returning early.
Tests may skip when the environment genuinely cannot exercise their contract;
make the reason clear.

Prefer `rstest` for parameterized tests; tests that do not need parameterization
can use their usual test attributes. When combining `rstest` with `test_log` or
`tokio`, use explicit `#[test_attr(...)]` wrappers to select the intended test
harness rather than relying on implicit test-attribute detection.

Run the relevant integration tests locally before submitting your pull request
when your environment supports them. See [Aya Integration Tests] for
instructions.

## Workflow Dependencies

Install GitHub's lockfile generator with
`gh extension install github/gh-actions-lock`. After editing workflows or
repository actions, regenerate and verify their dependencies:

```sh
gh actions-lock --no-narrow
gh actions-lock --verify
```

Commit `.github/workflows/actions.lock` with the workflow changes. The
`--no-narrow` option preserves major-version references such as `@v2`; the
lockfile records their exact commits. Dependabot groups action version bumps
into a monthly pull request and updates the corresponding lockfile entries.
If a tag or branch advances without changing its name, its locked commit stays
in place. Use `gh actions-lock --relock --no-narrow` to update those pins
manually.

## Source References

When citing another project's source code to justify a claim or explain
behavior, use a GitHub permalink pinned to a commit. Abbreviate the commit
SHA to nine hexadecimal digits.

Use full URLs for cross-repository references in commit messages.

## Documentation Style

If you find an API that is not documented, unclear or missing examples, please
file an issue. If you make changes to the documentation, please read
[How To Write Documentation] and make sure your changes conform to the
format outlined in [Documenting Components].

If you want to make changes to the Aya Book, see the README in the
[book repository].

["good first issue"]: https://github.com/aya-rs/aya/labels/good%20first%20issue
["help wanted"]: https://github.com/aya-rs/aya/labels/help%20wanted
[Aya Integration Tests]: https://github.com/aya-rs/aya/blob/main/test/README.md
[How To Write Documentation]: https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html
[Documenting Components]: https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html#documenting-components
[book repository]: https://github.com/aya-rs/book
[Discord]: https://discord.gg/xHW2cb2N6G
