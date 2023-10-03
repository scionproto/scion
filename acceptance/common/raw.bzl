load("//tools/lint:py.bzl", "py_binary", "py_library", "py_test")
load("@com_github_scionproto_scion_python_deps//:requirements.bzl", "requirement")

# Bug in bazel: HOME isn't set to TEST_TMPDIR.
# Bug in docker-compose v2.21 a writable HOME is required (eventhough not used).
# Poor design in Bazel, there's no sane way to obtain the path to some
# location that's not a litteral dependency.
# So, HOME must be provided by the invoker.
def raw_test(
        name,
        src,
        args = [],
        deps = [],
        data = [],
        tags = [],
        homedir = "",
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
            # Ensure that unicode output can be printed to the log/console
            "PYTHONIOENCODING": "utf-8",
            "HOME": homedir,
        },
    )
