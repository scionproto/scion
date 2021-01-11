load("@io_bazel_rules_docker//container:container.bzl", "container_bundle")
load("@rules_python//python:defs.bzl", "py_binary", "py_library", "py_test")
load("@pip3_deps//:requirements.bzl", "requirement")
load("//python/topology:topology.bzl", "topology")

# Creates a test based on a topology file. It creates a target specified
# by the 'name' argument that runs the entire test. Additionally, It
# creates <name>_setup, <name>_run and <name>_teardown targets that allow
# to run the test in stages.
#  name - name of the test
#  src - the source code of the test
#  topo - the topology (.topo) file to use for the test
#  gateway - whether gateways should be present in the topology
#  debug - if true, debug docker images are used instead of prod images
#  args - additional arguments to pass to the test
#  deps - additional dependencies
#  data - additional data files
#  tester - tester image to use
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
    py_library(
        name = "%s_lib" % name,
        srcs = [src],
        deps = [
            requirement("plumbum"),
            "//acceptance/common:base",
            "//acceptance/common:log",
            "//acceptance/common:tools",
        ] + deps,
        visibility = ["//visibility:public"],
    )

    common_args = [
        "--topology_tar",
        "$(location :%s_topo)" % name,
        "--containers_tar",
        "$(location :%s_containers.tar)" % name,
    ]
    common_data = [
        ":%s_containers.tar" % name,
        ":%s_topo" % name,
    ]

    py_binary(
        name = "%s_setup" % name,
        srcs = [src],
        args = ["setup"] + common_args,
        main = src,
        deps = [":%s_lib" % name],
        data = common_data,
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
        data = common_data,
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

    topology(
        name = "%s_topo" % name,
        src = topo,
        out = "%s_gen.tar" % name,
        sig = gateway,
    )
