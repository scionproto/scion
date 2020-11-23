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
        base = "@debian10//image",
        env = {"TZ": "UTC"},
        debs = [
            # iptables and its dependencies (only not already present)
            packages["gcc-8-base"],
            packages["iptables"],
            packages["libip4tc0"],
            packages["libip6tc0"],
            packages["libiptc0"],
            packages["libnetfilter-conntrack3"],
            packages["libnfnetlink0"],
            packages["libnftnl11"],
            packages["libxtables12"],
            # telnet and its dependencies (only not already present)
            packages["telnet"],
            packages["netbase"],
            # sysctl and dependencies
            packages["procps"],
            packages["libgpm2"],
            packages["libncurses6"],
            packages["libprocps7"],
            packages["lsb-base"],
            packages["psmisc"],
        ],
        tars = [
            ":share",
        ],
        workdir = "/share",
        cmd = "tail -f /dev/null",
        visibility = ["//visibility:public"],
    )
