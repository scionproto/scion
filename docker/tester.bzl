load("@rules_pkg//:pkg.bzl", "pkg_tar")
load("@io_bazel_rules_docker//container:container.bzl", "container_bundle", "container_image")
load("@packages_debian10//file:packages.bzl", "packages")
load("@io_bazel_rules_docker//docker/package_managers:download_pkgs.bzl", "download_pkgs")
load("@io_bazel_rules_docker//docker/package_managers:install_pkgs.bzl", "install_pkgs")

def build_tester_image():
    download_pkgs(
        name = "tester_pkgs",
        image_tar = "@debian10//image",
        packages = [
            "bridge-utils",
            "iperf",
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
        srcs = [":tester_files"],
        package_dir = "share",
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
        name = "tester",
        base = ":tester_pkgs_image.tar",
        env = {
            "TZ": "UTC",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/share/bin",
        },
        tars = [
            ":bbcp_binary",
            ":bbcp_sources",
            ":share",
        ],
        workdir = "/share",
        cmd = "tail -f /dev/null",
        visibility = ["//visibility:public"],
    )
