# Contributing Guide

* [New Contributor Guide](#contributing-guide)
  * [Ways to Contribute](#ways-to-contribute)
  * [Find an Issue](#find-an-issue)
  * [Ask for Help](#ask-for-help)
  * [Pull Request Lifecycle](#pull-request-lifecycle)
  * [Signoff Your Commits](#signoff-your-commits)
  * [Pull Request Checklist](#pull-request-checklist)
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
* Answering questions on Discord
* Web design
* Communications / Social Media / Blog Posts
* Release management

Not everything happens through a GitHub pull request. Please come to our
[Discord](https://discord.gg/xHW2cb2N6G) and let's discuss how we can work
together.

## Find an Issue

We have good first issues for new contributors and help wanted issues suitable
for any contributor. [good first issue](https://github.com/aya-rs/aya/labels/good%20first%20issue) has extra information to
help you make your first contribution. [help wanted](https://github.com/aya-rs/aya/labels/help%20wanted) are issues
suitable for someone who isn't a core maintainer and is good to move onto after
your first pull request.

Sometimes there won’t be any issues with these labels. That’s ok! There is
likely still something for you to work on. If you want to contribute but you
don’t know where to start or can't find a suitable issue, you can reach out to us on Discord and we will be happy to help.

Once you see an issue that you'd like to work on, please post a comment saying
that you want to work on it. Something like "I want to work on this" is fine.

## Ask for Help

The best way to reach us with a question when contributing is to ask on:

* The original github issue
* Our Discord

## Pull Request Lifecycle

Pull requests are managed by Mergify.

Our process is currently as follows:

1. When you open a PR a maintainer will automatically be assigned for review
1. Make sure that your PR is passing CI - if you need help with failing checks please feel free to ask!
1. Once it is passing all CI checks, a maintainer will review your PR and you may be asked to make changes.
1. When you have received at two approving reviews from a maintainer, your PR will be merged automiatcally.

In some cases, other changes may conflict with your PR. If this happens, you will get notified by a comment in the issue that your PR requires a rebase, and the `needs-rebase` label will be applied. Once a rebase has been performed, this label will be automatically removed.

## Signoff Your Commits

### DCO

Licensing is important to open source projects. It provides some assurances that
the software will continue to be available based under the terms that the
author(s) desired. We require that contributors sign off on commits submitted to
our project's repositories. The [Developer Certificate of Origin
(DCO)](https://probot.github.io/apps/dco/) is a way to certify that you wrote and
have the right to contribute the code you are submitting to the project.

You sign-off by adding the following to your commit messages. Your sign-off must
match the git user and email associated with the commit.

    This is my commit message

    Signed-off-by: Your Name <your.name@example.com>

Git has a `-s` command line option to do this automatically:

    git commit -s -m 'This is my commit message'

If you forgot to do this and have not yet pushed your changes to the remote
repository, you can amend your commit with the sign-off by running

    git commit --amend -s 

## Logical Grouping of Commits

It is a recommended best practice to keep your changes as logically grouped as
possible within individual commits. If while you're developing you prefer doing
a number of commits that are "checkpoints" and don't represent a single logical
change, please squash those together before asking for a review.
When addressing review comments, please perform an interactive rebase and edit commits directly rather than adding new commits with messages like "Fix review comments".

## Commit message guidelines

A good commit message should describe what changed and why.

1. The first line should:
  
* contain a short description of the change (preferably 50 characters or less,
    and no more than 72 characters)
* be entirely in lowercase with the exception of proper nouns, acronyms, and
    the words that refer to code, like function/variable names
* be prefixed with the name of the sub crate being changed

  Examples:

  * aya: validate program section names
  * aya-bpf: add dispatcher program test slot

2. Keep the second line blank.
3. Wrap all other lines at 72 columns (except for long URLs).
4. If your patch fixes an open issue, you can add a reference to it at the end
   of the log. Use the `Fixes: #` prefix and the issue number. For other
   references use `Refs: #`. `Refs` may include multiple issues, separated by a
   comma.

   Examples:

   * `Fixes: #1337`
   * `Refs: #1234`

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

Fixes: #1337
Refs: #453, #154
```

## Pull Request Checklist

When you submit your pull request, or you push new commits to it, our automated
systems will run some checks on your new code. We require that your pull request
passes these checks, but we also have more criteria than just that before we can
accept and merge it. We recommend that you check the following things locally
before you submit your code:

* That Rust code has been formatted with `cargo +nightly fmt` and that all clippy lints have been fixed - you can find failing lints with `cargo +nightly clippy`
* That Go code has been formatted and linted
* That unit tests are passing locally with `cargo test`
* That integration tests are passing locally `cargo xtask integration-test`

## Documentation Style

If you make changes to the documentation, please read
[How To Write Documentation](https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html)and make sure your changes conform to the format outlined [here](
https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html#documenting-components).
