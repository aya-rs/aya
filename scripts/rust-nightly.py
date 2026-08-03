#!/usr/bin/env python3

"""Manage the Rust nightly pinned by MODULE.bazel."""

from __future__ import annotations

import argparse
import datetime
import itertools
import re
import sys
import time
import tomllib
from http.client import IncompleteRead
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


NIGHTLY = re.compile(r"\bnightly([/-])(\d{4}-\d{2}-\d{2})\b")


def read_nightly(module: str) -> datetime.date:
    matches = list(NIGHTLY.finditer(module))
    if len(matches) != 1:
        raise ValueError("expected exactly one Rust nightly pin")
    return datetime.date.fromisoformat(matches[0].group(2))


def latest_nightly() -> datetime.date:
    for attempt in itertools.count():
        try:
            with urlopen(
                "https://static.rust-lang.org/dist/channel-rust-nightly.toml",
                timeout=60,
            ) as response:
                manifest: dict[str, object] = tomllib.load(response)
            break
        except HTTPError as error:
            if attempt == 5 or not (
                error.code in (408, 429) or 500 <= error.code < 600
            ):
                raise
        except (URLError, TimeoutError, ConnectionError, IncompleteRead):
            if attempt == 5:
                raise
        time.sleep(2**attempt)

    value = manifest.get("date")
    if not isinstance(value, str):
        raise ValueError("nightly manifest contains an invalid date")
    date = datetime.date.fromisoformat(value)
    if date.isoformat() != value:
        raise ValueError("nightly manifest contains an invalid date")

    return date


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("current")
    commands.add_parser("latest")
    update = commands.add_parser("update")
    update.add_argument("nightly")
    arguments = parser.parse_args()

    if arguments.command == "current":
        print(f"nightly-{read_nightly(sys.stdin.read()).isoformat()}")
        return

    if arguments.command == "latest":
        print(f"nightly-{latest_nightly().isoformat()}")
        return

    module = sys.stdin.read()
    current = read_nightly(module)

    match = re.fullmatch(r"nightly-(\d{4}-\d{2}-\d{2})", arguments.nightly)
    if match is None:
        raise ValueError("expected a dated Rust nightly")
    latest = datetime.date.fromisoformat(match.group(1))
    if latest < current:
        raise ValueError(f"Rust nightly regressed from {current} to {latest}")
    if latest == current:
        return

    updated = NIGHTLY.sub(
        lambda match: f"nightly{match.group(1)}{latest}", module
    )
    sys.stdout.write(updated)


if __name__ == "__main__":
    main()
