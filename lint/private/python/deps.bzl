load("@rules_python//python:pip.bzl", "pip_install")

def python_lint_deps():
    pip_install(
        name = "python_lint_pip_deps",
        requirements = "@com_github_scionproto_scion//lint/private/python:requirements.txt",
    )
