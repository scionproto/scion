# Copyright 2020 Anapaya Systems

from plumbum import local
from plumbum.machines import LocalMachine

from typing import Tuple
from pathlib import Path


def test(package: str) -> Tuple[int, str, str]:
    """
    Runs the Go tests in package. Set argument go_from_bazel to true to retrieve
    the go binary from the bazel cache.

    The return value is a (retcode, stdout, stderr) plumbum tuple.
    """

    local.env["ACCEPTANCE"] = 1
    go = _go_cmd()
    go = go["test", package]
    return go.run(retcode=None)


def _go_cmd() -> LocalMachine:
    bazel_info_output = local["bazel"]("info", "output_base")
    # Remove new line at end of output
    base_path = bazel_info_output.strip()
    go_bin_path = Path(base_path) / "external" / "go_sdk" / "bin" / "go"
    return local[str(go_bin_path)]
