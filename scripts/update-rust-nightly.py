#!/usr/bin/env python3

"""Inspect or update the Rust nightly pinned by MODULE.bazel."""

from __future__ import annotations

import datetime
import os
import re
import sys
import time
import tomllib
from http.client import IncompleteRead
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


MODULE = Path.cwd() / "MODULE.bazel"
NIGHTLY = re.compile(r"\bnightly([/-])(\d{4}-\d{2}-\d{2})\b")


def read_nightly(module: str) -> datetime.date:
    matches = list(NIGHTLY.finditer(module))
    if len(matches) != 1:
        raise ValueError("expected exactly one Rust nightly pin")
    return datetime.date.fromisoformat(matches[0].group(2))


def latest_nightly() -> datetime.date:
    for attempt in range(6):
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


def write_output(date: datetime.date) -> None:
    output = f"rust-nightly=nightly-{date.isoformat()}\n"
    print(output, end="")
    if path := os.getenv("GITHUB_OUTPUT"):
        with open(path, "a", encoding="utf-8") as destination:
            destination.write(output)


def main() -> None:
    arguments = sys.argv[1:]
    if arguments not in ([], ["update"]):
        raise SystemExit(f"usage: {sys.argv[0]} [update]")

    module = MODULE.read_text(encoding="utf-8")
    current = read_nightly(module)
    if not arguments:
        write_output(current)
        return

    latest = latest_nightly()
    if latest < current:
        raise ValueError(f"nightly manifest regressed from {current} to {latest}")
    if latest == current:
        return

    updated = NIGHTLY.sub(
        lambda match: f"nightly{match.group(1)}{latest}", module
    )
    MODULE.write_text(updated, encoding="utf-8")
    write_output(latest)


if __name__ == "__main__":
    main()
