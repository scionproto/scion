load("@rules_pkg//:pkg.bzl", "pkg_tar")
load("@io_bazel_rules_docker//container:container.bzl", "container_image")
load("@package_bundle//file:packages.bzl", "packages")
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

    # Environment variables to set.
    env = {"TZ": "UTC"}

    # Base for prod images.
    container_image(
        name = "app_base",
        base = "@distroless//base:static_debian9",
        env = env,
        debs = debs,
        tars = [
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
#   caps - capabilities to set on the binary
def scion_app_images(name, binary, appdir, workdir, entrypoint, caps = None):
    pkg_tar(
        name = "%s_docker_files" % name,
        srcs = [binary],
        package_dir = appdir,
        mode = "0755",
    )
    container_image_setcap(
        name = name + "_prod",
        repository = "scion",
        base = "//docker:app_base",
        tars = [":%s_docker_files" % name],
        workdir = workdir,
        entrypoint = entrypoint,
        caps_binary = "%s/%s" % (appdir, name),
        caps = caps,
    )
    container_image_setcap(
        name = name + "_debug",
        repository = "scion",
        base = "//docker:app_base_debug",
        tars = [":%s_docker_files" % name],
        workdir = workdir,
        entrypoint = entrypoint,
        caps_binary = "%s/%s" % (appdir, name),
        caps = caps,
    )
