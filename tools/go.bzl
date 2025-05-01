load("@io_bazel_rules_go//go:def.bzl", _go_test = "go_test")

def go_test(name, **kwargs):
    tags = kwargs.get("tags", [])
    if "integration" not in tags and "manual" not in tags:
        tags = tags + ["unit"]
    kwargs["tags"] = tags
    _go_test(name = name, **kwargs)
