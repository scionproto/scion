load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository", "new_git_repository")

_BBCP_BUILD = """
package(default_visibility = ["//visibility:public"])

# TODO(sustrik): make this hermetic
genrule(
    name = "bbcp_binary",
    srcs = glob(["**"]),
    outs = ["bbcp"],
    cmd = "pushd $$(dirname $(location src/Makefile)); make; popd; " +
        "cp $$(dirname $(location src/Makefile))/../bin/amd64_linux/bbcp $(@D)",
)

filegroup(
    name = "bbcp_sources",
    srcs = glob(["**"]),
)
"""

def bbcp_repository():
    new_git_repository(
        name = "com_github_eeertekin_bbcp",
        commit = "64af83266da5ebb3fdc2f012ac7f5ce0230bc648",
        remote = "https://github.com/eeertekin/bbcp.git",
        shallow_since = "1462187049 +0300",
        build_file_content = _BBCP_BUILD,
    )
