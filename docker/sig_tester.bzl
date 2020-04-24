load("@rules_pkg//:pkg.bzl", "pkg_tar")
load("@io_bazel_rules_docker//container:container.bzl", "container_bundle", "container_image")
load("@package_bundle//file:packages.bzl", "packages")

def build_sigtester_image():
    pkg_tar(
        name = "sig_entrypoint",
        srcs = ["files/sig.sh"],
        package_dir = "/share",
    )

    container_image(
        name = "scion_sig_acceptance_nocap",
        base = "@ubuntu16//image",
        env = {"TZ": "UTC"},
        debs = [
            packages["libc6"],
            # needed by su-exec
            packages["libgcc1"],
            packages["libstdc++6"],
            # needed for sig.sh
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
            ":app_base_files",
            ":sig_docker_files",
            ":sig_entrypoint",
        ],
        workdir = "/share",
        entrypoint = ["./sig.sh"],
    )
