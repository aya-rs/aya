#!/usr/bin/env python3

"""Inspect or update the Rust nightly pinned by MODULE.bazel."""

from __future__ import annotations

import datetime
import re
import sys
from pathlib import Path

from nightly import NightlyManifest, Pin, main


NIGHTLY = re.compile(
    r'^([ \t]*version[ \t]*=[ \t]*")nightly/(\d{4}-\d{2}-\d{2})(",?)$',
    re.MULTILINE,
)


def read_pin(module: str) -> Pin:
    matches = list(NIGHTLY.finditer(module))
    if len(matches) != 1:
        raise ValueError("expected exactly one Rust nightly pin")
    date = matches[0].group(2)
    datetime.date.fromisoformat(date)
    return Pin(f"nightly-{date}")


def update_module(
    module: str, current: Pin, nightly: str, manifest: NightlyManifest
) -> str | None:
    if nightly == current.nightly:
        return None
    date = nightly.removeprefix("nightly-")
    updated, count = NIGHTLY.subn(
        lambda match: f"{match.group(1)}nightly/{date}{match.group(3)}",
        module,
    )
    if count != 1:
        raise ValueError("expected exactly one Rust nightly pin")
    return updated


if __name__ == "__main__":
    sys.exit(
        main(Path(__file__).resolve().parent.parent / "MODULE.bazel", read_pin, update_module)
    )
