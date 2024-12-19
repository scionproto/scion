load("@aspect_bazel_lib//lib:copy_file.bzl", "copy_file")
load("@rules_oci//oci:defs.bzl", "oci_image", "oci_tarball")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")
load("@tester_debian10_packages//:packages.bzl", "debian_package_layer")

def scion_tester_image():
    pkg_tar(
        name = "tester_layer_packages",
        deps = [
            debian_package_layer("bridge-utils"),
            debian_package_layer("iperf3"),
            debian_package_layer("iptables"),
            debian_package_layer("netcat-openbsd"),
            debian_package_layer("openssh-server"),
            debian_package_layer("openssh-client"),
            debian_package_layer("procps"),
            debian_package_layer("telnet"),
            debian_package_layer("tshark"),
            debian_package_layer("wget"),
        ],
    )

    pkg_tar(
        name = "tester_layer_bin",
        srcs = [
            "//tools/end2end:end2end",
            "//scion/cmd/scion",
            "//scion-pki/cmd/scion-pki:scion-pki",
        ],
        package_dir = "share/bin",
    )

    pkg_tar(
        name = "tester_layer_tools_integration",
        srcs = [
            "//tools/integration:bin_wrapper.sh",
        ],
        package_dir = "share/tools/integration",
    )

    pkg_tar(
        name = "tester_layer_share",
        srcs = native.glob(["files/*"]),
        package_dir = "share",
    )

    oci_image(
        name = "tester",
        base = "@debian10",
        env = {
            "TZ": "UTC",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/share/bin",
        },
        workdir = "/share",
        cmd = ["tail", "-f", "/dev/null"],
        tars = [
            ":tester_layer_packages",
            ":tester_layer_share",
            ":tester_layer_tools_integration",
            ":tester_layer_bin",
        ],
        labels = ":labels",
        visibility = ["//visibility:public"],
    )
    oci_tarball(
        name = "tester.load",
        format = "docker",
        image = "tester",
        repo_tags = ["scion/tester:latest"],
    )

    # see comment on scion_app.bzl
    copy_file(
        name = "tester.tarball",
        src = "tester.load",
        out = "tester.tar",
        visibility = ["//visibility:public"],
    )
