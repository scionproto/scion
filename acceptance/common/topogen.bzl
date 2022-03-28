load("//tools/lint:py.bzl", "py_binary", "py_library", "py_test")
load("@pip3_deps//:requirements.bzl", "requirement")

def topogen_test(
        name,
        src,
        topo,
        gateway = False,
        debug = False,
        args = [],
        deps = [],
        data = [],
        tester = "//docker:tester"):
    """Creates a test based on a topology file.

    It creates a target specified by the 'name' argument that runs the entire
    test. Additionally, It creates <name>_setup, <name>_run and <name>_teardown
    targets that allow to run the test in stages.

    Args:
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
            requirement("plumbum"),
            "//acceptance/common:base",
            "//acceptance/common:log",
            "//acceptance/common:docker",
        ] + deps,
        visibility = ["//visibility:public"],
    )

    setup_params = " "
    if gateway:
        setup_params += " --sig"

    common_args = [
        "--executables=scion-pki:$(location //scion-pki/cmd/scion-pki)",
        "--executables=topogen:$(location //tools:topogen)",
        "--topo=$(location %s)" % topo,
        "--setup-params='%s'" % setup_params,
    ]
    common_data = [
        "//scion-pki/cmd/scion-pki",
        "//tools:topogen",
        "//tools:docker_ip",
        topo,
    ]
    loaders = container_loaders(tester, gateway)
    for tag in loaders:
        loader = loaders[tag]
        common_data = common_data + ["%s" % loader]
        common_args = common_args + ["--container_loader=%s#$(location %s)" % (tag, loader)]

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
        },
    )

def container_loaders(tester, gateway):
    images = {
        "control:latest": "//docker:control",
        "daemon:latest": "//docker:daemon",
        "dispatcher:latest": "//docker:dispatcher",
        "tester:latest": tester,
        "posix-router:latest": "//docker:posix_router",
    }
    if gateway:
        images["posix-gateway:latest"] = "//docker:posix_gateway"
    return images
