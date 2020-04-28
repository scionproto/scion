load("@bazel_tools//tools/build_defs/pkg:pkg.bzl", "pkg_tar")
load("@io_bazel_rules_docker//container:container.bzl", "container_image")
load("@package_bundle//file:packages.bzl", "packages")

# Defines a common base image for all app images.
def scion_app_base():
    # Debian packages to install.
    debs = [
        packages["libc6"],
        # we need setcap so that we can add network capabilities to apps
        packages["libcap2"],
        packages["libcap2-bin"],
        # needed by su-exec
        packages["libgcc1"],
        packages["libstdc++6"],
    ]

    # Install su-exec.
    pkg_tar(
        name = "app_base_files",
        srcs = [
            "@com_github_anapaya_su_exec//:su-exec",
        ],
        remap_paths = {
            "": "sbin",
        },
        mode = "0755",
    )

    # Environment variables to set.
    env = {"TZ": "UTC"}

    # Base for prod images.
    container_image(
        name = "app_base",
        base = "@distroless//base:static_debian9",
        env = env,
        debs = debs,
        tars = [
            ":app_base_files",
            "//licenses:licenses",
        ],
        visibility = ["//visibility:public"],
    )

    # base for debug images.
    container_image(
        name = "app_base_debug",
        base = "@distroless//base:debug_debian9",
        env = env,
        debs = debs,
        tars = [
            ":app_base_files",
            "//licenses:licenses",
        ],
        visibility = ["//visibility:public"],
    )

# Defines images for a specific SCION application.
# Creates "{name}_prod" and "{name}_debug" targets.
#   name - name of the rule
#   binary - the target that builds the app binary
#   appdir - the directory to deploy the binary to
#   workdir - working directory
#   entrypoint - a list of strings that add up to the command line
#   stamp - whether to stamp the created images (default=True).
def scion_app_images(name, binary, appdir, workdir, entrypoint, stamp = True):
    pkg_tar(
        name = name + "_docker_files",
        srcs = [binary],
        package_dir = appdir,
        mode = "0755",
    )

    container_image(
        name = name + "_prod",
        repository = "scion",
        base = "//docker:app_base",
        tars = [":" + name + "_docker_files"],
        workdir = workdir,
        entrypoint = ["/sbin/su-exec"] + entrypoint,
        stamp = stamp,
        visibility = ["//visibility:public"],
    )

    container_image(
        name = name + "_debug",
        repository = "scion",
        base = "//docker:app_base_debug",
        tars = [":" + name + "_docker_files"],
        workdir = workdir,
        entrypoint = entrypoint,
        stamp = stamp,
        visibility = ["//visibility:public"],
    )
