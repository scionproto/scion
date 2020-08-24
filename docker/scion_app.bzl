load("@rules_pkg//:pkg.bzl", "pkg_tar")
load("@io_bazel_rules_docker//container:container.bzl", "container_image")
load("@package_bundle//file:packages.bzl", "packages")
load(":caps.bzl", "setcap")

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
#   caps - capabilities to set on the binary
def scion_app_images(name, binary, appdir, workdir, entrypoint, caps = None):
    pkg_tar(
        name = "%s_docker_files" % name,
        srcs = [binary],
        package_dir = appdir,
        mode = "0755",
    )
    scion_app_images_internal(
        "prod",
        "//docker:app_base",
        name,
        binary,
        appdir,
        workdir,
        ["/sbin/su-exec"] + entrypoint,
        caps,
    )
    scion_app_images_internal(
        "debug",
        "//docker:app_base_debug",
        name,
        binary,
        appdir,
        workdir,
        entrypoint,
        caps,
    )

def scion_app_images_internal(suffix, base, name, binary, appdir, workdir, entrypoint, caps):
    if not caps:
        container_image(
            name = "%s_%s" % (name, suffix),
            repository = "scion",
            base = base,
            tars = [":%s_docker_files" % name],
            workdir = workdir,
            entrypoint = entrypoint,
            visibility = ["//visibility:public"],
        )
    else:
        container_image(
            name = "%s_%s_nocap" % (name, suffix),
            repository = "scion",
            base = base,
            tars = [":%s_docker_files" % name],
            workdir = workdir,
            entrypoint = entrypoint,
        )
        setcap(
            name = "%s_%s_withcap" % (name, suffix),
            image = "%s_%s_nocap.tar" % (name, suffix),
            caps = caps,
            binary = "%s/%s" % (appdir, name),
        )
        container_image(
            name = "%s_%s" % (name, suffix),
            base = "%s_%s_withcap.tar" % (name, suffix),
            visibility = ["//visibility:public"],
        )
