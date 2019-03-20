load("@bazel_tools//tools/build_defs/pkg:pkg.bzl", "pkg_tar")
load("@io_bazel_rules_docker//container:container.bzl", "container_image")
load("@package_bundle//file:packages.bzl", "packages")

# Defines a common base image for all app images.
def scion_app_base():

    # A tarball containing licenses of the dependencies.
    # If the rule is run on a freshly cloned repository, the tarball will be empty.
    # However, the process of building the base container copies the licenses
    # to the licenses subdirectory and these rules then put them into a tarball.
    native.filegroup(
        name = "uncompressed",
        srcs = native.glob(["licenses/**"]),
    )
    pkg_tar(
        name = "licenses",
        package_dir = "/licenses",
        srcs = [":uncompressed"],
        mode = "0444",
    )

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
        base = "@distroless//base",
        env = env,
        debs = debs,
        tars = [
            ":app_base_files",
            ":licenses",
        ],
        visibility = ["//visibility:public"],
    )

    # base for debug images.
    container_image(
        name = "app_base_debug",
        base = "@distroless//base:debug",
        env = env,
        debs = debs,
        tars = [
            ":app_base_files",
            ":licenses",
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
def scion_app_images(name, binary, appdir, workdir, entrypoint):
    pkg_tar(
        name = name + "_docker_files",
        srcs = [binary],
        package_dir = appdir,
        mode = "0755",
    )

    container_image(
        name = name + "_prod",
        repository = "scion",
        base = "//docker/perapp:app_base",
        tars = [":" + name + "_docker_files"],
        workdir = workdir,
        entrypoint = ["/sbin/su-exec"] + entrypoint,
        stamp = True,
        visibility = ["//visibility:public"],
    )

    container_image(
        name = name + "_debug",
        repository = "scion",
        base = "//docker/perapp:app_base_debug",
        tars = [":" + name + "_docker_files"],
        workdir = workdir,
        entrypoint = ["/sbin/su-exec"] + entrypoint,
        stamp = True,
        visibility = ["//visibility:public"],
    )
