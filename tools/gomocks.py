#!/usr/bin/env python3

import os
import pathlib
from typing import List
from typing import Tuple

import plumbum
from plumbum import cli, cmd
from plumbum.path.utils import delete


def rule_to_file(rule: str) -> Tuple[str, str]:
    """
    Converts the bazel rule name into a pair of paths to mock files. The first
    path is the mock file in the bazel tree, and the second one is the path in
    the workspace tree.
    """
    if not rule.startswith("//"):
        raise ValueError("invalid rule name: '%s', must start with //" % rule)
    if ":" not in rule:
        raise ValueError("invalid rule name: '%s', must contain :" % rule)
    package = rule.split(":")[0][2:]
    return (os.path.join('bazel-bin', package, "mock.go"),
            os.path.join(package, "mock.go"))


def mock_rules() -> List[str]:
    bazel = plumbum.local['bazel']
    raw_rules = bazel("query", "filter(\"go_default_mock$\", kind(gomock, //...))")
    return raw_rules.splitlines()


class GoMocks(cli.Application):
    """
    Tool to update all mocked Go files in the repository. For adding a new mock
    please use the `add` subcommand.
    """

    def main(self):
        if self.nested_command:
            return
        self.update_files()

    def update_files(self):
        rules = mock_rules()
        bazel = plumbum.local['bazel']
        print("building mock files...")
        bazel("build", rules)
        for rule in rules:
            print(rule)
            bf, wf = rule_to_file(rule)
            cmd.cp(bf, wf)
            cmd.chmod("0644", wf)


@GoMocks.subcommand("diff")
class Diff(GoMocks):
    """
    Checks the difference between generated files and the files in the worktree.
    """
    def main(self):
        rules = mock_rules()
        bazel = plumbum.local['bazel']
        bazel("build", rules)
        for rule in rules:
            bf, wf = rule_to_file(rule)
            cmd.diff(bf, wf)


@GoMocks.subcommand("add")
class Add(GoMocks):
    """
    Adds a new gomock file. Note that for existing mocks the current generation
    rule is overridden. Thus, to add a single interface to an existing generation
    rule, all interfaces need to be specified.
    """

    package = cli.SwitchAttr("--package", str, mandatory=True,
                             help="The package directory, relatively to the SCION root dir")
    interfaces = cli.SwitchAttr("--interfaces", str, mandatory=True,
                                help="The interfaces to mock, separated by comma")

    def main(self):
        self.package = self.package.rstrip("/")
        package_path = plumbum.local.path(self.package)
        name = package_path.name
        mock_path = plumbum.local.path(package_path / "mock_%s" % name)
        delete(mock_path // "*.go")
        buildscript = """
load("@io_bazel_rules_go//go:def.bzl", "gomock")
gomock(
    name = "go_default_mock",
    out = "mock.go",
    interfaces = %s,
    library = "//%s:go_default_library",
    package = "mock_%s",
)
""" % (self.interfaces.split(","), self.package, name)
        pathlib.Path(mock_path).mkdir(parents=True, exist_ok=True)
        pathlib.Path(mock_path / "BUILD.bazel").write_text(buildscript)
        mock_rule = "//%s:go_default_mock" % os.path.join(self.package, "mock_%s" % name)
        bazel = plumbum.local['bazel']
        bazel("build", mock_rule)
        bf, wf = rule_to_file(mock_rule)
        cmd.cp(bf, wf)
        cmd.chmod("0644", wf)
        cmd.make("gazelle")


if __name__ == "__main__":
    GoMocks.run()
