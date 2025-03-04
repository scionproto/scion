load("@aspect_bazel_lib//lib:tar.bzl", "tar")
load("@aspect_bazel_lib//lib:copy_file.bzl", "copy_file")
load("@rules_distroless//apt:index.bzl", "deb_index")
load("@rules_oci//oci:defs.bzl", "oci_image", "oci_tarball")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")

# NOTE: This list needs to be in-sync with tester_deb.yaml
# We could potentially generate this with a buildozer rule if it becomes
# too cumbersome to maintain.
PACKAGES = [
    "@tester_deb//bash",
    "@tester_deb//bridge-utils",
    "@tester_deb//iperf3",
    "@tester_deb//iproute2",
    "@tester_deb//iptables",
    "@tester_deb//iputils-ping",
    "@tester_deb//net-tools",
    "@tester_deb//netcat-openbsd",
    "@tester_deb//openssh-client",
    "@tester_deb//openssh-server",
    "@tester_deb//procps",
    "@tester_deb//rsync",
    "@tester_deb//telnet",
    "@tester_deb//tshark",
    "@tester_deb//wget",
]

def declare_tester_deb():
    deb_index(
        name = "tester_deb",
        lock = "//docker:tester_deb.lock.json",
        manifest = "//docker:tester_deb.yaml",
    )

def scion_tester_image():
    # Required to avoid https://github.com/GoogleContainerTools/rules_distroless/issues/36
    pkg_tar(
        name = "tester_layer_deb",
        deps = [
            "%s/amd64" % package
            for package in PACKAGES
        ],
    )

    tar(
        name = "tester_layer_sh_symlink",
        mtree = [
            "./usr/bin/sh type=link link=/usr/bin/bash",
            "./bin type=link link=/usr/bin mode=0777 uid=0 gid=0",
        ],
    )

    remap_deb_tars(
        name = "tester_layer_deb_remapped",
        src = "tester_layer_deb",
        out = "tester_layer_deb_remapped.tar",
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
            ":tester_layer_deb_remapped",
            ":tester_layer_sh_symlink",
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

def remap_deb_tars(name, src, out):
    # The tars created by rules_distroless have proper directories instead of symlinks
    # which overwrite the symlinks in the base image. This will result in a broken image.
    # To counter this, we move the contents of the supposedly symlinked sources to the
    # symlink target directories, remove the source directories and create symlinks to the
    # target directories.
    #
    # See: https://github.com/GoogleContainerTools/rules_distroless/issues/53
    native.genrule(
        name = name,
        srcs = [src],
        outs = [out],
        cmd = " ; ".join([
            "SCRATCH=$$(mktemp -d )",
            "REALOUT=$$(realpath $@)",
            "mkdir -p $$SCRATCH/bundle",
            "echo $$SCRATCH/bundle",
            "echo debug",
            "echo $$PATH",
            "tar -xf $(location " + src + ") -C $$SCRATCH/bundle",
            "cd $$SCRATCH/bundle",
            "[ -e bin ] && rsync -av bin/ usr/bin/ && rm -rf bin && ln -s /usr/bin bin || true",
            "[ -e sbin ] && rsync -av sbin/ usr/sbin/ && rm -rf sbin && ln -s /usr/sbin sbin || true",
            "[ -e lib ] && rsync -av lib/ usr/lib/ && rm -rf lib && ln -s /usr/lib lib || true",
            "[ -e lib64 ] && rsync -av lib64/ usr/lib64/ && rm -rf lib64 && ln -s /usr/lib64 lib64 || true",
            "[ -e var/run ] && rsync -av var/run/ run/ && rm -rf var/run && ln -s /run var/run || true",
            "[ -e var/lock ] && rsync -av var/lock/ run/lock/ && rm -rf var/lock && ln -s /run/lock var/lock || true",
            "tar --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2019-01-01' -cf $$REALOUT .",
            "rm -rf $$SCRATCH",
        ]),
    )
