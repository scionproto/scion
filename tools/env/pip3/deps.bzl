""" Python dependency declaration """

load("@rules_python//python:pip.bzl", "pip_parse")

def python_deps(interpreter):
    pip_parse(
        name = "com_github_scionproto_scion_python_deps",
        python_interpreter_target = interpreter,
        requirements = "@com_github_scionproto_scion//tools/env/pip3:requirements.txt",
    )
