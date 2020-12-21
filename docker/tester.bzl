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
            "files/ssh_setup.sh",
            "files/id_rsa",
            "files/id_rsa.pub",
            "files/ssh_config",
        ],
        package_dir = "share",
    )

    container_image(
        name = "tester",
        base = "@debian10//image",
        env = {
            "TZ": "UTC",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/share/bin",
        },
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
            # iperf
            packages["iperf"],
        ],
        tars = [
            ":share",
        ],
        workdir = "/share",
        cmd = "tail -f /dev/null",
        visibility = ["//visibility:public"],
    )

    pkg_tar(
        name = "bbcp_binary",
        srcs = ["@com_github_eeertekin_bbcp//:bbcp_binary"],
        mode = "0755",
        package_dir = "bin",
    )

    pkg_tar(
        name = "bbcp_sources",
        srcs = ["@com_github_eeertekin_bbcp//:bbcp_sources"],
        mode = "0444",
        package_dir = "src",
    )

    container_image(
        name = "bbcp_tester",
        base = ":tester",
        debs = [
            # dependencies of bbcp
            packages["openssh-server"],
            packages["openssh-client"],
            packages["libssl1.1"],
            packages["libwrap0"],
            packages["libkrb5-3"],
            packages["libgssapi-krb5-2"],
            packages["libk5crypto3"],
            packages["libkrb5support0"],
            packages["libkeyutils1"],
            # dependecies of brctl
            packages["bridge-utils"],
        ],
        tars = [
            ":bbcp_binary",
            ":bbcp_sources",
        ],
        cmd = "tail -f /dev/null",
        visibility = ["//visibility:public"],
    )
