load("@rules_pkg//:pkg.bzl", "pkg_tar")
load("@rules_oci//oci:defs.bzl", "oci_image", "oci_tarball")

# Defines a common base image for all app images.
def scion_app_base():
    pkg_tar(
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

    # Currently in opensource there are tests (reload_X) that are doing
    # shell commands into the container. We need to change that behavior
    # and once we do that we should only use the prod thin image without
    # shell.
    oci_image(
        name = "app_base",
        base = "@distroless_base_debian10",
        env = env,
        tars = [
            "//licenses:licenses",
            ":share_dirs_layer",
        ],
        visibility = ["//visibility:public"],
    )

# Defines images for a specific SCION application.
# Creates "{name}" targets.
#   name - name of the rule
#   src - the target that builds the app binary
#   appdir - the directory to deploy the binary to
#   workdir - working directory
#   entrypoint - a list of strings that add up to the command line
#   cmd - string or list of strings of commands to execute in the image.
#   caps - capabilities to set on the binary
#
# Target {name}.tar is the docker image tarball.
#
# Load the image into docker with
#   bazel run //path:name.load
def scion_app_image(name, src, entrypoint, appdir = "/app", workdir = "/share", cmd = None, caps = None, caps_binary = None):
    pkg_tar(
        name = "%s_docker_files" % name,
        srcs = [src],
        package_dir = appdir,
        mode = "0755",
    )
    oci_image(
        name = name,
        base = "//docker:app_base",
        tars = [":%s_docker_files" % name],
        workdir = workdir,
        entrypoint = entrypoint,
        cmd = cmd,
        visibility = ["//visibility:public"],
    )
    ### XXX(matzf):
    # This oci_tarball rule does two things: with `bazel build` it  _builds_ the tarball, and with `bazel run` it _loads_ it into docker.
    # Weirdly, "$(location //path/name.load)" expands to the shell script to _load_ the tarball but only the actual tarball file is symlinked into the test directories.
    # I don't know if I deeply messed up, or bazel is just going of the rails here.
    # As a workaround, pack the whole thing in a filegroup which only keeps the tarball. ugh
    oci_tarball(
        name = name + ".load",
        format = "docker",
        image = name,
        repo_tags = ["scion/" + name + ":latest"],
        visibility = ["//visibility:public"],
    )
    native.filegroup(
        name = name + ".tar",
        srcs = [ name + ".load" ],
        visibility = ["//visibility:public"],
    )
