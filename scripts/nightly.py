"""Shared infrastructure for inspecting and advancing pinned Rust nightlies.

Callers provide their own pin parser and update strategy. This module owns
nightly discovery, retry handling, monotonic updates, and opaque workflow
outputs without depending on any caller-specific pin format.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import json
import os
import re
import sys
import time
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from http.client import HTTPResponse, IncompleteRead
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
SHA = r"[0-9a-f]{40}"


@dataclass(frozen=True)
class Pin:
    nightly: str
    metadata: dict[str, str] = field(default_factory=dict)


def match_one(pattern: str, text: str, name: str) -> str:
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {name}")
    return matches[0].group(1)


def replace_one(text: str, pattern: str, value: str, name: str) -> str:
    result, count = re.subn(pattern, lambda _: value, text, flags=re.MULTILINE)
    if count != 1:
        raise ValueError(f"expected exactly one {name}")
    return result


def open_url(url: str):
    headers = {"User-Agent": "aya-rs Rust nightly updater"}
    if url.startswith("https://api.github.com/") and (token := os.getenv("GH_TOKEN")):
        headers |= {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
        }
    return urlopen(Request(url, headers=headers), timeout=60)


def fetch(url: str, consume: Callable[[HTTPResponse], bytes]) -> bytes:
    for attempt in range(6):
        try:
            with open_url(url) as response:
                return consume(response)
        except HTTPError as error:
            if attempt == 5 or not (
                error.code in (408, 429) or 500 <= error.code < 600
            ):
                raise
        except (URLError, TimeoutError, ConnectionError, IncompleteRead):
            if attempt == 5:
                raise
        time.sleep(2**attempt)
    raise AssertionError("unreachable")


def download(url: str) -> bytes:
    return fetch(url, lambda response: response.read())


def latest_nightly() -> tuple[str, dict[str, Any]]:
    manifest = tomllib.loads(
        download("https://static.rust-lang.org/dist/channel-rust-nightly.toml").decode(
            "utf-8"
        )
    )
    date = manifest["date"]
    if not isinstance(date, str) or DATE.fullmatch(date) is None:
        raise ValueError("nightly manifest contains an invalid date")
    return f"nightly-{datetime.date.fromisoformat(date).isoformat()}", manifest


def write_outputs(pin: Pin, module: str | None = None) -> None:
    outputs = {"rust-nightly": pin.nightly}
    if pin.metadata:
        outputs["metadata"] = json.dumps(pin.metadata, separators=(",", ":"))
    if module is not None:
        outputs["module"] = base64.b64encode(module.encode("utf-8")).decode()
    rendered = "".join(f"{name}={value}\n" for name, value in outputs.items())
    print(rendered, end="")
    if output := os.getenv("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as destination:
            destination.write(rendered)


def main(
    module: Path,
    read_pin: Callable[[str], Pin],
    update: Callable[[str, Pin, str, dict[str, Any]], str | None],
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--module",
        type=Path,
        default=module,
        help="MODULE.bazel to inspect or update",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="update MODULE.bazel to the latest supported Rust nightly",
    )
    args = parser.parse_args()
    try:
        text = args.module.read_text(encoding="utf-8")
        current = read_pin(text)
        if not args.update:
            write_outputs(current)
            return 0

        nightly, manifest = latest_nightly()
        if nightly < current.nightly:
            raise ValueError(
                "nightly manifest regressed from "
                f"{current.nightly.removeprefix('nightly-')} to "
                f"{nightly.removeprefix('nightly-')}"
            )
        # Adapters may update pinned inputs without changing the nightly date.
        updated = update(text, current, nightly, manifest)
        if updated is None:
            return 0

        candidate = read_pin(updated)
        args.module.write_text(updated, encoding="utf-8")
        write_outputs(candidate, updated)
        return 0
    except (IncompleteRead, KeyError, OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
