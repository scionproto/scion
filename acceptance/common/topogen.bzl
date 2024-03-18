load("//tools/lint:py.bzl", "py_binary", "py_library", "py_test")
load("@com_github_scionproto_scion_python_deps//:requirements.bzl", "requirement")

# Bug in bazel: HOME isn't set to TEST_TMPDIR.
# Bug in docker-compose v2.21 a writable HOME is required (eventhough not used).
# Poor design in Bazel, there's no sane way to obtain the path to some
# location that's not a litteral dependency.
# So, HOME must be provided by the invoker.
def topogen_test(
        name,
        src,
        topo,
        gateway = False,
        debug = False,
        args = [],
        deps = [],
        data = [],
        homedir = "",
        tester = "//docker:tester.tarball"):
    """Creates a test based on a topology file.

    It creates a target specified by the 'name' argument that runs the entire
    test. Additionally, It creates <name>_setup, <name>_run and <name>_teardown
    targets that allow to run the test in stages.

    Args:cc
        name: name of the test
        src: the source code of the test
        topo: the topology (.topo) file to use for the test
        gateway: whether gateways should be present in the topology
        debug: if true, debug docker images are used instead of prod images
        args: additional arguments to pass to the test
        deps: additional dependencies
        data: additional data files
        tester: tester image to use
    """

    py_library(
        name = "%s_lib" % name,
        srcs = [src],
        deps = [
            requirement("pyyaml"),
            requirement("plumbum"),
            "//acceptance/common:base",
            "//acceptance/common:log",
            "//acceptance/common:docker",
        ] + deps,
        visibility = ["//visibility:public"],
    )

    common_args = [
        "--executable=scion-pki:$(location //scion-pki/cmd/scion-pki)",
        "--executable=topogen:$(location //tools:topogen)",
        "--executable=await-connectivity:$(location //tools:await_connectivity)",
        "--topo=$(location %s)" % topo,
    ]
    if gateway:
        common_args.append("--setup-params='--sig'")

    common_data = [
        "//scion-pki/cmd/scion-pki",
        "//tools:topogen",
        "//tools:docker_ip",
        "//tools:await_connectivity",
        topo,
    ]
    docker_images = [
        "//docker:control.tarball",
        "//docker:daemon.tarball",
        "//docker:dispatcher.tarball",
        "//docker:router.tarball",
    ]
    if tester:
        docker_images += [tester]
    if gateway:
        docker_images += ["//docker:gateway.tarball"]

    for tar in docker_images:
        common_data = common_data + [tar]
        common_args = common_args + ["--docker-image=$(location %s)" % tar]

    py_binary(
        name = "%s_setup" % name,
        srcs = [src],
        args = ["setup"] + common_args,
        main = src,
        deps = [":%s_lib" % name],
        data = data + common_data,
    )

    py_binary(
        name = "%s_run" % name,
        srcs = [src],
        args = ["run"] + args + common_args,
        main = src,
        deps = [":%s_lib" % name],
        data = data + common_data,
    )

    py_binary(
        name = "%s_teardown" % name,
        srcs = [src],
        args = ["teardown"] + common_args,
        main = src,
        deps = [":%s_lib" % name],
        data = data + common_data,
    )

    py_test(
        name = name,
        size = "large",
        srcs = [src],
        main = src,
        args = args + common_args,
        deps = [":%s_lib" % name],
        data = data + common_data,
        tags = ["integration", "exclusive"],
        env = {
            # Ensure output appears immediately (in particular with --test_output=streamed)
            "PYTHONUNBUFFERED": "1",
            # Ensure that unicode output can be printed to the log/console
            "PYTHONIOENCODING": "utf-8",
            "HOME": homedir,
        },
    )
