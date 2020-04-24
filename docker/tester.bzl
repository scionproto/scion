load("@rules_pkg//:pkg.bzl", "pkg_tar")
load("@io_bazel_rules_docker//container:container.bzl", "container_bundle", "container_image")
load("@package_bundle//file:packages.bzl", "packages")

def build_tester_image():
    pkg_tar(
        name = "bin",
        srcs = [
            "//go/integration/cert_req:cert_req",
            "//go/integration/end2end:end2end",
            "//go/examples/pingpong:pingpong",
            "//go/tools/scmp:scmp",
            "//go/tools/showpaths:showpaths",
        ],
        package_dir = "bin",
    )

    pkg_tar(
        name = "integration",
        srcs = [
            "//integration:bin_wrapper.sh",
        ],
        package_dir = "integration",
    )

    pkg_tar(
        name = "share",
        deps = [
            ":bin",
            ":integration",
        ],
        srcs = [
            "files/tester.sh",
        ],
        package_dir = "share",
    )

    container_image(
        name = "scion_tester",
        base = "@ubuntu16//image",
        env = {"TZ": "UTC"},
        debs = [
            packages["libc6"],
            # ping and its dependencies
            packages["iputils-ping"],
            packages["libidn11"],
            packages["libnettle6"],
            # iproute2 and its dependencies
            packages["iproute2"],
            packages["libelf1"],
            packages["libmnl0"],
        ],
        tars = [
            ":share",
        ],
        workdir = "/share",
        cmd = "tail -f /dev/null",
    )
