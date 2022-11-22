load("@rules_pkg//:pkg.bzl", "pkg_tar")
load("@io_bazel_rules_docker//container:container.bzl", "container_image")
load("@io_bazel_rules_docker//docker/package_managers:download_pkgs.bzl", "download_pkgs")
load("@io_bazel_rules_docker//docker/package_managers:install_pkgs.bzl", "install_pkgs")

def build_tester_image():
    download_pkgs(
        name = "tester_pkgs",
        image_tar = "@debian10//image",
        packages = [
            "bridge-utils",
            "iperf3",
            "iptables",
            "netcat-openbsd",
            "openssh-server",
            "openssh-client",
            "procps",
            "telnet",
            "tshark",
            "wget",
        ],
    )

    install_pkgs(
        name = "tester_pkgs_image",
        image_tar = "@debian10//image",
        installables_tar = ":tester_pkgs.tar",
        installation_cleanup_commands = "rm -rf /var/lib/apt/lists/*",
        output_image_name = "tester_pkgs_image",
    )

    pkg_tar(
        name = "bin",
        srcs = [
            "//tools/end2end:end2end",
            "//scion/cmd/scion",
            "//scion-pki/cmd/scion-pki:scion-pki",
        ],
        package_dir = "bin",
    )

    pkg_tar(
        name = "integration",
        srcs = [
            "//tools/integration:bin_wrapper.sh",
        ],
        package_dir = "tools/integration",
    )

    pkg_tar(
        name = "share",
        deps = [
            ":bin",
            ":integration",
        ],
        srcs = [":tester_files"],
        package_dir = "share",
    )

    container_image(
        name = "tester",
        base = ":tester_pkgs_image.tar",
        env = {
            "TZ": "UTC",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/share/bin",
        },
        tars = [
            ":share",
        ],
        workdir = "/share",
        cmd = "tail -f /dev/null",
        visibility = ["//visibility:public"],
    )
