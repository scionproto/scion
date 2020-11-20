load("@rules_pkg//:pkg.bzl", "pkg_tar")
load("@io_bazel_rules_docker//container:container.bzl", "container_image", "container_layer")
load("@packages_debian10//file:packages.bzl", "packages")
load(":caps.bzl", "container_image_setcap")

# Defines a common base image for all app images.
def scion_app_base():
    # Debian packages to install.
    debs = [
        packages["libc6"],
        # we need setcap so that we can add network capabilities to apps
        packages["libcap2"],
        packages["libcap2-bin"],
    ]

    container_layer(
        name = "share_dirs_layer",
        empty_dirs = [
            "/share/cache",
            "/share/data",
            "/share/data/trustdb",
        ],
        mode = "0777",
    )

    # Environment variables to set.
    env = {"TZ": "UTC"}

    # Base for prod images.
    container_image(
        name = "app_base",
        base = "@static_debian10//image",
        env = env,
        debs = debs,
        tars = [
            "//licenses:licenses",
        ],
        layers = [":share_dirs_layer"],
        visibility = ["//visibility:public"],
    )

    # base for debug images.
    container_image(
        name = "app_base_debug",
        base = "@debug_debian10//image",
        env = env,
        debs = debs,
        tars = [
            "//licenses:licenses",
        ],
        layers = [":share_dirs_layer"],
        visibility = ["//visibility:public"],
    )

    pkg_tar(
        name = "delve_bin",
        srcs = [
            "@com_github_go_delve_delve//cmd/dlv",
        ],
        package_dir = "bin",
    )

# Defines images for a specific SCION application.
# Creates "{name}_prod" and "{name}_debug" targets.
#   name - name of the rule
#   src - the target that builds the app binary
#   appdir - the directory to deploy the binary to
#   workdir - working directory
#   entrypoint - a list of strings that add up to the command line
#   cmd - string or list of strings of commands to execute in the image.
#   caps - capabilities to set on the binary
def scion_app_images(name, src, entrypoint, appdir = "/app", workdir = "/share", cmd = None, caps = None, caps_binary = None):
    pkg_tar(
        name = "%s_docker_files" % name,
        srcs = [src],
        package_dir = appdir,
        mode = "0755",
    )
    container_image_setcap(
        name = name + "_prod",
        repository = "scion",
        base = "//docker:app_base",
        tars = [":%s_docker_files" % name],
        workdir = workdir,
        cmd = cmd,
        entrypoint = entrypoint,
        caps_binary = caps_binary,
        caps = caps,
    )
    container_image_setcap(
        name = name + "_debug",
        repository = "scion",
        base = "//docker:app_base_debug",
        tars = [":%s_docker_files" % name, "//docker:delve_bin"],
        workdir = workdir,
        cmd = cmd,
        entrypoint = entrypoint,
        caps_binary = caps_binary,
        caps = caps,
    )
