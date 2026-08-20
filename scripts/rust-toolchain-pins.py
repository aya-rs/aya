#!/usr/bin/env python3

"""Read and update Aya's Rust toolchain declarations with Buildozer."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from rust_toolchains import Channel, Toolchain, read_toolchain, selection_key


TOOLCHAINS = {
    Channel.STABLE: "stable_rust_toolchains",
    Channel.NIGHTLY: "default_rust_toolchains",
}
MODULE = Path("MODULE.bazel").resolve()


def read_pins(text: str) -> dict[Channel, Toolchain]:
    value = json.loads(text)
    if not isinstance(value, dict) or value.keys() != TOOLCHAINS.keys():
        raise ValueError("expected stable and nightly Rust toolchains")
    return {channel: read_toolchain(value[channel], channel) for channel in TOOLCHAINS}


def buildozer(*commands: str) -> str:
    result = subprocess.run(
        [
            "bazel",
            "run",
            "--lockfile_mode=error",
            "@buildifier_prebuilt//:buildozer",
            "--",
            "-f",
            "-",
        ],
        input="\n".join(commands) + "\n",
        stdout=subprocess.PIPE,
        text=True,
    )
    # Buildozer returns 3 when an edit leaves the file unchanged.
    if result.returncode not in (0, 3):
        result.check_returncode()
    return result.stdout


def current_toolchain(channel: Channel) -> str:
    version = buildozer(f"print version|{MODULE}:{TOOLCHAINS[channel]}").strip()
    rust = version.replace("/", "-", 1)
    selection_key(rust, channel)
    return rust


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    current = commands.add_parser("current")
    current.add_argument("channel", type=Channel, choices=list(TOOLCHAINS))
    update = commands.add_parser("update")
    update.add_argument("toolchains", type=read_pins)
    arguments = parser.parse_args()

    if arguments.command == "current":
        print(current_toolchain(arguments.channel))
        return

    candidates: dict[Channel, Toolchain] = arguments.toolchains
    edits = []
    for channel, candidate in candidates.items():
        previous = current_toolchain(channel)
        if selection_key(candidate.rust, channel) < selection_key(previous, channel):
            raise ValueError(
                f"Rust {channel} regressed from {previous} to {candidate.rust}"
            )
        if candidate.rust != previous:
            version = candidate.rust.replace("-", "/", 1)
            edits.append(f"set version {version}|{MODULE}:{TOOLCHAINS[channel]}")

    # Validate both channels before asking Buildozer to write the file once.
    if edits:
        buildozer(*edits)


if __name__ == "__main__":
    main()
