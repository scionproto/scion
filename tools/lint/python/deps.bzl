""" Lint dependency declaration """

load("@rules_python//python:pip.bzl", "pip_parse")

def python_lint_deps(interpreter):
    pip_parse(
        name = "com_github_scionproto_scion_python_lint_deps",
        python_interpreter_target = interpreter,
        requirements = "@com_github_scionproto_scion//tools/lint/python:requirements.txt",
    )
