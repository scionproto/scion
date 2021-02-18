load("@apple_rules_lint//lint:defs.bzl", "get_lint_config")
load(
    "@rules_python//python:defs.bzl",
    _py_binary = "py_binary",
    _py_library = "py_library",
    _py_test = "py_test",
)
load("//lint/private/python:flake8.bzl", "flake8_test")

def _add_py_lint_tests(name, **kwargs):
    tags = kwargs.get("tags", [])
    flake8 = get_lint_config("flake8", tags)
    srcs = kwargs.get("srcs", [])
    if len(srcs) == 0:
        return

    flake8_test(
        name = "%s-flake8" % name,
        srcs = srcs,
        lint_config = flake8,
        tags = tags + ["lint", "flake8"],
        size = "small",
    )

def py_library(name, **kwargs):
    _add_py_lint_tests(name, **kwargs)
    _py_library(name = name, **kwargs)

def py_binary(name, **kwargs):
    _add_py_lint_tests(name, **kwargs)
    _py_binary(name = name, **kwargs)

def py_test(name, **kwargs):
    _add_py_lint_tests(name, **kwargs)
    tags = kwargs.get("tags", [])
    if "integration" not in tags and "manual" not in tags:
        tags = tags + ["unit"]
    kwargs["tags"] = tags
    _py_test(name = name, **kwargs)
