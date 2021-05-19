load("@io_bazel_rules_docker//container:container.bzl", "container_bundle")
load("//lint:py.bzl", "py_binary", "py_library", "py_test")
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
        "--executables=scion-pki:$(location //go/scion-pki)",
        "--executables=crypto_lib.sh:$(location //scripts/cryptoplayground:crypto_lib.sh)",
        "--executables=topogen:$(location //python/topology:topogen)",
        "--topo=$(location %s)" % topo,
        "--containers_tar=$(location :%s_containers.tar)" % name,
        "--setup-params='%s'" % setup_params,
    ]
    common_data = [
        "//scripts/cryptoplayground:crypto_lib.sh",
        "//go/scion-pki",
        "//python/topology:topogen",
        "//tools:docker_ip",
        topo,
        ":%s_containers.tar" % name,
    ]

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
        tags = ["integration"],
    )

    images = {
        "control:latest": "//docker:control",
        "daemon:latest": "//docker:daemon",
        "dispatcher:latest": "//docker:dispatcher",
        "tester:latest": tester,
        "posix-router:latest": "//docker:posix_router",
    }
    if gateway:
        images["posix-gateway:latest"] = "//docker:posix_gateway"

    container_bundle(
        name = "%s_containers" % name,
        images = images,
    )
