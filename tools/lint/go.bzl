load("@apple_rules_lint//lint:defs.bzl", "get_lint_config")
load("@io_bazel_rules_go//go:def.bzl", _go_library = "go_library", _go_test = "go_test")

def go_library(name, **kwargs):
    _go_library(name = name, **kwargs)

def go_test(name, **kwargs):
    tags = kwargs.get("tags", [])
    if "integration" not in tags and "manual" not in tags:
        tags = tags + ["unit"]
    kwargs["tags"] = tags
    _go_test(name = name, **kwargs)
