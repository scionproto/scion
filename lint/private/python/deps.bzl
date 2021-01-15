load("@rules_python//python:pip.bzl", "pip_install")

def python_lint_deps():
    pip_install(
        name = "python_lint_pip_deps",
        requirements = "//lint/private/python:requirements.txt",
    )
