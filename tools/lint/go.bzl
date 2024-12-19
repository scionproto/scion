load("@apple_rules_lint//lint:defs.bzl", "get_lint_config")
load("@io_bazel_rules_go//go:def.bzl", _go_library = "go_library", _go_test = "go_test")
load(":impi.bzl", "impi_test")
load(":ineffassign.bzl", "ineffassign_test")

def _add_go_lint_tests(name, **kwargs):
    tags = kwargs.get("tags", [])
    go_lint = get_lint_config("go", tags)
    srcs = kwargs.get("srcs", [])
    if len(srcs) == 0:
        return

    impi_test(
        name = "%s-impi" % name,
        srcs = srcs,
        lint_config = go_lint,
        tags = tags + ["lint", "impi"],
        size = "small",
    )
    ineffassign_test(
        name = "%s-ineffassign" % name,
        srcs = srcs,
        lint_config = go_lint,
        tags = tags + ["lint", "ineffassign"],
        size = "small",
    )

def go_library(name, **kwargs):
    _add_go_lint_tests(name, **kwargs)
    _go_library(name = name, **kwargs)

def go_test(name, **kwargs):
    _add_go_lint_tests(name, **kwargs)
    tags = kwargs.get("tags", [])
    if "integration" not in tags and "manual" not in tags:
        tags = tags + ["unit"]
    kwargs["tags"] = tags
    _go_test(name = name, **kwargs)
