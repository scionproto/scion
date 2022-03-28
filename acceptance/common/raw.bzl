load("//tools/lint:py.bzl", "py_binary", "py_library", "py_test")
load("@pip3_deps//:requirements.bzl", "requirement")

def raw_test(
        name,
        src,
        args = [],
        deps = [],
        data = [],
        tags = [],
        local = False):
    py_library(
        name = "%s_lib" % name,
        srcs = [src],
        deps = [
            requirement("plumbum"),
            "@com_github_scionproto_scion//acceptance/common:base",
            "@com_github_scionproto_scion//acceptance/common:log",
            "@com_github_scionproto_scion//acceptance/common:docker",
        ] + deps,
        visibility = ["//visibility:public"],
    )

    py_binary(
        name = "%s_setup" % name,
        srcs = [src],
        args = ["setup"] + args,
        main = src,
        deps = [":%s_lib" % name],
        data = data,
    )

    py_binary(
        name = "%s_run" % name,
        srcs = [src],
        args = ["run"] + args,
        main = src,
        deps = [":%s_lib" % name],
        data = data,
    )

    py_binary(
        name = "%s_teardown" % name,
        srcs = [src],
        args = ["teardown"],
        main = src,
        deps = [":%s_lib" % name],
        data = data,
    )

    py_test(
        name = name,
        size = "large",
        srcs = [src],
        main = src,
        args = args,
        deps = [":%s_lib" % name],
        data = data,
        tags = tags + ["integration", "exclusive"],
        local = local,
        env = {
            # Ensure output appears immediately (in particular with --test_output=streamed)
            "PYTHONUNBUFFERED": "1",
        },
    )
