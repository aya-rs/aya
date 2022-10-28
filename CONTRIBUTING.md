# Contributing to Aya

Thanks for your help improving the project!

## Reporting issues

If you believe you've discovered a bug in aya, please check if the bug is
already known or [create an issue](https://github.com/aya-rs/aya/issues) on
github. Please also report an issue if you find documentation that you think is
confusing or could be improved.

When creating a new issue, make sure to include as many details as possible to
help us understand the problem. When reporting a bug, always specify which
version of aya you're using and which version of the linux kernel.

## Documentation

If you find an API that is not documented, unclear or missing examples, please
file an issue. If you make changes to the documentation, please read
https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html and make sure
your changes conform to the format outlined here
https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html#documenting-components.

If you want to make changes to the Aya Book, see the readme in the book repo
https://github.com/aya-rs/book.

## Fixing bugs and implementing new features

Make sure that your work is tracked by an issue or a (draft) pull request, this
helps us avoid duplicating work. If your work includes publicly visible changes,
make sure those are properly documented as explained in the section above.

### Running tests
Run the unit tests with `cargo test`. See [Aya Integration Tests](https://github.com/aya-rs/aya/blob/main/test/README.md) regarding running the integration tests.

### Commits

It is a recommended best practice to keep your changes as logically grouped as
possible within individual commits. If while you're developing you prefer doing
a number of commits that are "checkpoints" and don't represent a single logical
change, please squash those together before asking for a review.

#### Commit message guidelines

A good commit message should describe what changed and why.

1. The first line should:

  * contain a short description of the change (preferably 50 characters or less,
    and no more than 72 characters)
  * be entirely in lowercase with the exception of proper nouns, acronyms, and
    the words that refer to code, like function/variable names
  * be prefixed with the name of the sub crate being changed

  Examples:

  * aya: handle reordered functions
  * aya-bpf: SkSkbContext: add ::l3_csum_replace

2. Keep the second line blank.
3. Wrap all other lines at 72 columns (except for long URLs).
4. If your patch fixes an open issue, you can add a reference to it at the end
   of the log. Use the `Fixes: #` prefix and the issue number. For other
   references use `Refs: #`. `Refs` may include multiple issues, separated by a
   comma.

   Examples:

   - `Fixes: #1337`
   - `Refs: #1234`

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
