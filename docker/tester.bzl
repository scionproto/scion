load("@rules_pkg//:pkg.bzl", "pkg_tar")
load("@io_bazel_rules_docker//container:container.bzl", "container_bundle", "container_image")
load("@packages_debian10//file:packages.bzl", "packages")

def build_tester_image():
    pkg_tar(
        name = "bin",
        srcs = [
            "//go/integration/end2end:end2end",
            "//go/scion",
            "//go/scion-pki:scion-pki",
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
            "files/sig_setup.sh",
        ],
        package_dir = "share",
    )

    container_image(
        name = "tester",
        base = "@ubuntu16//image",
        env = {"TZ": "UTC"},
        debs = [
            packages["libc6"],
            # ping and its dependencies
            packages["iputils-ping"],
            packages["libcap2"],
            packages["libcap2-bin"],
            packages["libidn2-0"],
            packages["libunistring2"],
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
        visibility = ["//visibility:public"],
    )
