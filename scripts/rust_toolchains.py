#!/usr/bin/env python3

"""Resolve Rust channels to immutable toolchains and rustc commits."""

from __future__ import annotations

import argparse
import datetime
import json
import re
import time
import tomllib
from enum import StrEnum
from http.client import IncompleteRead
from typing import NamedTuple
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


DIST = "https://static.rust-lang.org/dist"
RELEASE = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
SHA = r"[0-9a-f]{40}"


class Channel(StrEnum):
    STABLE = "stable"
    BETA = "beta"
    NIGHTLY = "nightly"


class Toolchain(NamedTuple):
    rust: str
    rustc_commit: str

    def as_json(self) -> dict[str, str]:
        return {"rust": self.rust, "rustc-commit": self.rustc_commit}


def selection_key(rust: str, channel: Channel) -> tuple[int, int, int]:
    if channel == Channel.STABLE:
        match = re.fullmatch(RELEASE, rust)
        if match is None:
            raise ValueError("expected a full Rust release version")
        major, minor, patch = match.groups()
        return int(major), int(minor), int(patch)
    prefix, separator, value = rust.partition("-")
    if prefix != channel or not separator:
        raise ValueError(f"expected a dated Rust {channel}")
    date = datetime.date.fromisoformat(value)
    if date.isoformat() != value:
        raise ValueError(f"expected a dated Rust {channel}")
    return date.year, date.month, date.day


def read_toolchain(value: object, channel: Channel) -> Toolchain:
    if not isinstance(value, dict):
        raise ValueError(f"invalid Rust {channel} toolchain")
    rust = value.get("rust")
    commit = value.get("rustc-commit")
    if (
        not isinstance(rust, str)
        or not isinstance(commit, str)
        or re.fullmatch(SHA, commit) is None
    ):
        raise ValueError(f"invalid Rust {channel} toolchain")
    selection_key(rust, channel)
    return Toolchain(rust, commit)


def read_manifest(url: str) -> dict[str, object]:
    attempt = 0
    while True:
        try:
            with urlopen(url, timeout=60) as response:
                return tomllib.load(response)
        except HTTPError as error:
            if attempt == 5 or not (
                error.code in (408, 429) or 500 <= error.code < 600
            ):
                raise
        except (URLError, TimeoutError, ConnectionError, IncompleteRead):
            if attempt == 5:
                raise
        time.sleep(2**attempt)
        attempt += 1


def manifest_toolchain(manifest: dict[str, object], channel: Channel) -> Toolchain:
    packages = manifest.get("pkg")
    if not isinstance(packages, dict):
        raise ValueError(f"{channel} manifest contains no package metadata")
    rustc = packages.get("rustc")
    if not isinstance(rustc, dict):
        raise ValueError(f"{channel} manifest contains no rustc metadata")
    if channel == Channel.STABLE:
        version = rustc.get("version")
        if not isinstance(version, str):
            raise ValueError("stable manifest contains an invalid Rust version")
        rust = version.partition(" ")[0]
    else:
        value = manifest.get("date")
        if not isinstance(value, str):
            raise ValueError(f"{channel} manifest contains an invalid date")
        rust = f"{channel}-{value}"

    return read_toolchain(
        {"rust": rust, "rustc-commit": rustc.get("git_commit_hash")}, channel
    )


def resolve(channel: Channel) -> Toolchain:
    latest = manifest_toolchain(
        read_manifest(f"{DIST}/channel-rust-{channel}.toml"), channel
    )
    if channel == Channel.STABLE:
        path = f"channel-rust-{latest.rust}.toml"
    else:
        date = latest.rust.removeprefix(f"{channel}-")
        path = f"{date}/channel-rust-{channel}.toml"
    immutable = manifest_toolchain(read_manifest(f"{DIST}/{path}"), channel)
    if immutable.rust != latest.rust:
        raise ValueError(f"{channel} manifest does not match the resolved toolchain")
    if immutable.rustc_commit != latest.rustc_commit:
        raise ValueError(f"{channel} manifest does not match the resolved rustc commit")
    return immutable


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("channels", nargs="+", type=Channel, choices=list(Channel))
    arguments = parser.parse_args()
    toolchains: dict[Channel, dict[str, str]] = {}
    for channel in dict.fromkeys(arguments.channels):
        toolchains[channel] = resolve(channel).as_json()
    print(json.dumps(toolchains, separators=(",", ":")))


if __name__ == "__main__":
    main()
