# Aya Project Governance

The Aya project is dedicated to creating the best user experience when using
eBPF from Rust, whether that's in user-land or kernel-land. This governance
explains how the project is run.

- [Values](#values)
- [Maintainers](#maintainers)
- [Becoming a Maintainer](#becoming-a-maintainer)
- [Meetings](#meetings)
- [Code of Conduct Enforcement](#code-of-conduct)
- [Security Response Team](#security-response-team)
- [Voting](#voting)
- [Modifications](#modifying-this-charter)

## Values

The Aya project and its leadership embrace the following values:

- Openness: Communication and decision-making happens in the open and is
  discoverable for future reference. As much as possible, all discussions and
  work take place in public forums and open repositories.

- Fairness: All stakeholders have the opportunity to provide feedback and submit
  contributions, which will be considered on their merits.

- Community over Product or Company: Sustaining and growing our community takes
  priority over shipping code or sponsors' organizational goals. Each
  contributor participates in the project as an individual.

- Inclusivity: We innovate through different perspectives and skill sets, which
  can only be accomplished in a welcoming and respectful environment.

- Participation: Responsibilities within the project are earned through
  participation, and there is a clear path up the contributor ladder into
  leadership positions.

## Maintainers

Aya Maintainers have write access to the all projects in the
[GitHub organization]. They can merge their patches or patches from others.
The list of current maintainers can be found at [MAINTAINERS.md].
Maintainers collectively manage the project's resources and contributors.

This privilege is granted with some expectation of responsibility: maintainers
are people who care about the Aya project and want to help it grow and
improve. A maintainer is not just someone who can make changes, but someone who
has demonstrated their ability to collaborate with the team, get the most
knowledgeable people to review code and docs, contribute high-quality code, and
follow through to fix issues (in code or tests).

A maintainer is a contributor to the project's success and a citizen helping
the project succeed.

The collective team of all Maintainers is known as the Maintainer Council, which
is the governing body for the project.

### Becoming a Maintainer

To become a Maintainer, you need to demonstrate a commitment to the project, an
ability to write quality code and/or documentation, and an ability to
collaborate with the team. The following list is an example of the
the kind of contributions that would be expected to be promoted to Maintainer
status however there is no strict requirement for all points to be met:

- Commitment to the project, as evidenced by:
  - Participate in discussions, contributions, code and documentation reviews,
    for 6 months or more.
  - Perform reviews for 10 non-trivial pull requests.
  - Contribute 10 non-trivial pull requests and have them merged.
- Ability to write quality code and/or documentation.
- Ability to collaborate with the team.
- Understanding of how the team works (policies, processes for testing
  and code review, etc).
- Understanding of the project's code base and coding and documentation style.

A new Maintainer must be proposed by an existing maintainer by opening a
Pull Request on GitHub to update the MAINTAINERS.md file. A simple majority vote
of existing Maintainers approves the application. Maintainer nominations will be
evaluated without prejudice to employers or demographics.

Maintainers who are selected will be granted the necessary GitHub rights.

### Removing a Maintainer

Maintainers may resign at any time if they feel that they will not be able to
continue fulfilling their project duties. Resignations should be communicated
via GitHub Pull Request to update the [MAINTAINERS.md] file. Approving
resignations does not require a vote.

Maintainers may also be removed after being inactive, failing to fulfill their
Maintainer responsibilities, violating the Code of Conduct, or for other reasons.
Inactivity is defined as a period of very low or no activity in the project
for a year or more, with no definite schedule to return to full Maintainer
activity.

The process for removing a maintainer is for an existing maintainer to open
a Pull Request on GitHub to update the [MAINTAINERS.md] file. The commit
message should explain the reason for removal. The Pull Request will be
voted on by the remaining maintainers. A 2/3 majority vote is required to
remove a maintainer.

Depending on the reason for removal, a Maintainer may be converted to Emeritus
status. Emeritus Maintainers will still be consulted on some project matters
and can be rapidly returned to Maintainer status if their availability changes.
However, Emeritus Maintainers will not have write access to the project's
repositories.

The process for making an Emeritus Maintainer is the same as for removing a
Maintainer, except that the [MAINTAINERS.md] file should be updated to reflect
the Emeritus status rather than removing the Maintainer entirely.

The process for returning an Emeritus Maintainer is via Pull Request
to update the [MAINTAINERS.md] file. A simple majority vote of existing
Maintainers approves the return.

## Meetings

There are no standing meetings for Maintainers.

Maintainers may have closed meetings to discuss security reports
or Code of Conduct violations. Such meetings should be scheduled by any
Maintainer on receipt of a security issue or CoC report. All current Maintainers
must be invited to such closed meetings, except for any Maintainer who is
accused of a CoC violation.

## Code of Conduct

[Code of Conduct] violations by community members will be
discussed and resolved on the private maintainer Discord channel.

## Security Response Team

The Maintainers will appoint a Security Response Team to handle security
reports. This committee may simply consist of the Maintainer Council themselves.
If this responsibility is delegated, the Maintainers will appoint a team of at
least two contributors to handle it. The Maintainers will review who is assigned
to this at least once a year.

The Security Response Team is responsible for handling all reports of security
holes and breaches according to the [security policy].

## Voting

While most business in Aya is conducted by [lazy consensus], periodically the
Maintainers may need to vote on specific actions or changes.
A vote can be taken on the private developer Discord channel for security or
conduct matters. Any Maintainer may demand a vote be taken.

Most votes require a simple majority of all Maintainers to succeed, except where
otherwise noted. Two-thirds majority votes mean at least two-thirds of all
existing maintainers.

## Modifying this Charter

Changes to this Governance and its supporting documents may be approved by
a 2/3 vote of the Maintainers.

[GitHub organization]: https://github.com/aya-rs
[Code of Conduct]: ./CODE_OF_CONDUCT.md
[MAINTAINERS.md]: ./MAINTAINERS.md
[security policy]: ./SECURITY.md
[lazy consensus]: https://community.apache.org/committers/lazyConsensus.html
