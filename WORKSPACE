# Generic stuff for dealing with repositories.
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

# Bazel rules for Golang
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "7b9bbe3ea1fccb46dcfa6c3f3e29ba7ec740d8733370e21cdc8937467b4a4349",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.22.4/rules_go-v0.22.4.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.22.4/rules_go-v0.22.4.tar.gz",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_download_sdk", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

go_download_sdk(
    name = "go_sdk",
    sdks = {
        "linux_amd64": ("go1.13.10.linux-amd64.tar.gz", "8a4cbc9f2b95d114c38f6cbe94a45372d48c604b707db2057c787398dfbf8e7f"),
    },
)

go_register_toolchains(nogo = "@//:nogo")

# Gazelle
http_archive(
    name = "bazel_gazelle",
    sha256 = "d8c45ee70ec39a57e7a05e5027c32b1576cc7f16d9dd37135b0eddde45cf1b10",
    urls = [
        "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/bazel-gazelle/releases/download/v0.20.0/bazel-gazelle-v0.20.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.20.0/bazel-gazelle-v0.20.0.tar.gz",
    ],
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

gazelle_dependencies()

# XXX Needs to be before rules_docker
# Python rules
git_repository(
    name = "rules_python",
    commit = "94677401bc56ed5d756f50b441a6a5c7f735a6d4",
    remote = "https://github.com/bazelbuild/rules_python.git",
    shallow_since = "1573842889 -0500",
)

load("@rules_python//python:repositories.bzl", "py_repositories")

py_repositories()

load("@rules_python//python:pip.bzl", "pip3_import")

pip3_import(
    name = "pip3_deps",
    requirements = "//env/pip3:requirements.txt",
)

load("@pip3_deps//:requirements.bzl", "pip_install")

pip_install()

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "rules_pkg",
    sha256 = "352c090cc3d3f9a6b4e676cf42a6047c16824959b438895a76c2989c6d7c246a",
    urls = [
        "https://github.com/bazelbuild/rules_pkg/releases/download/0.2.5/rules_pkg-0.2.5.tar.gz",
        "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/0.2.5/rules_pkg-0.2.5.tar.gz",
    ],
)

load("@rules_pkg//:deps.bzl", "rules_pkg_dependencies")

rules_pkg_dependencies()

# Docker rules
http_archive(
    name = "io_bazel_rules_docker",
    sha256 = "dc97fccceacd4c6be14e800b2a00693d5e8d07f69ee187babfd04a80a9f8e250",
    strip_prefix = "rules_docker-0.14.1",
    urls = ["https://github.com/bazelbuild/rules_docker/releases/download/v0.14.1/rules_docker-v0.14.1.tar.gz"],
)

load("@io_bazel_rules_docker//repositories:repositories.bzl", container_repositories = "repositories")

container_repositories()

load("@io_bazel_rules_docker//repositories:deps.bzl", container_deps = "deps")

container_deps()

load("@io_bazel_rules_docker//go:image.bzl", _go_image_repos = "repositories")

_go_image_repos()

# Distroless
git_repository(
    name = "distroless",
    commit = "48dba0a4ace4fcb4fdd8d7e1f7dc1a9ed8b38f7c",
    remote = "https://github.com/GoogleContainerTools/distroless.git",
    shallow_since = "1582150737 -0500",
)

# Debian packages to install in containers
load("@distroless//package_manager:package_manager.bzl", "package_manager_repositories")
load("@distroless//package_manager:dpkg.bzl", "dpkg_list", "dpkg_src")

package_manager_repositories()

dpkg_src(
    name = "debian_stretch",
    arch = "amd64",
    distro = "stretch",
    sha256 = "2b13362808b7bd90d24db2e0804c799288694ae44bd7e3d123becc191451fc67",
    snapshot = "20191028T085816Z",
    url = "https://snapshot.debian.org/archive",
)

dpkg_src(
    name = "debian_stretch_backports",
    arch = "amd64",
    distro = "stretch-backports",
    sha256 = "e9170a8f37a1bbb8ce2df49e6ab557d65ef809d19bf607fd91bcf8ba6b85e3f6",
    snapshot = "20191028T085816Z",
    url = "https://snapshot.debian.org/archive",
)

dpkg_src(
    name = "debian_stretch_security",
    package_prefix = "https://snapshot.debian.org/archive/debian-security/20191028T085816Z/",
    packages_gz_url = "https://snapshot.debian.org/archive/debian-security/20191028T085816Z/dists/stretch/updates/main/binary-amd64/Packages.gz",
    sha256 = "acea7d952d8ab84de3cd2c26934a1bcf5ad244d344ecdb7b2d0173712bbd9d7b",
)

dpkg_list(
    name = "package_bundle",
    packages = [
        "libc6",
        "libcap2",
        "libcap2-bin",
        "libgcc1",
        "libstdc++6",
        # These are needed by distroless.
        "base-files",
        "ca-certificates",
        "libssl1.1",
        "netbase",
        "openssl",
        "tzdata",
        # Needed by sig acceptance
        # ping and its dependencies
        "iputils-ping",
        "libidn11",
        "libnettle6",
        # iproute2 and its dependencies
        "iproute2",
        "libelf1",
        "libmnl0",
    ],
    sources = [
        "@debian_stretch_security//file:Packages.json",
        "@debian_stretch_backports//file:Packages.json",
        "@debian_stretch//file:Packages.json",
    ],
)

dpkg_src(
    name = "debian10",
    arch = "amd64",
    distro = "buster",
    sha256 = "ca19e4187523f4b087a2e7aaa2662c6a0b46dc81ff2f3dd44d9c5d95df0df212",
    snapshot = "20191028T085816Z",
    url = "https://snapshot.debian.org/archive",
)

dpkg_src(
    name = "debian10_security",
    package_prefix = "https://snapshot.debian.org/archive/debian-security/20191028T085816Z/",
    packages_gz_url = "https://snapshot.debian.org/archive/debian-security/20191028T085816Z/dists/buster/updates/main/binary-amd64/Packages.gz",
    sha256 = "dace61a2f1c4031f33dbc78e416a7211fad9946a3d997e96256561ed92b034be",
)

dpkg_list(
    name = "package_bundle_debian10",
    packages = [
        "libc6",
        "libcap2",
        "libcap2-bin",
        "libgcc1",
        "libstdc++6",
        # These are needed by distroless.
        "base-files",
        "ca-certificates",
        "libssl1.1",
        "netbase",
        "openssl",
        "tzdata",
    ],
    sources = [
        "@debian10_security//file:Packages.json",
        "@debian10//file:Packages.json",
    ],
)

load("@io_bazel_rules_docker//container:container.bzl", "container_pull")

container_pull(
    name = "ubuntu16",
    digest = "sha256:a98d9dcf3a34b2b78e78c61d003eb4d7a90d30fd54451686e2f0bd2ef5f602ac",
    registry = "index.docker.io",
    repository = "library/ubuntu",
    tag = "16.04",
)

# su-exec (used in app docker images)
git_repository(
    name = "com_github_anapaya_su_exec",
    commit = "d7253c2eb8987067834bc7d2fb7bd0c7958ce1ff",
    remote = "https://github.com/Anapaya/su-exec.git",
)

# Busybox (used in debug docker images)
http_file(
    name = "busybox",
    executable = True,
    sha256 = "b51b9328eb4e60748912e1c1867954a5cf7e9d5294781cae59ce225ed110523c",
    urls = ["https://busybox.net/downloads/binaries/1.27.1-i686/busybox"],
)

# Protobuf
http_archive(
    name = "com_google_protobuf",
    sha256 = "9748c0d90e54ea09e5e75fb7fac16edce15d2028d4356f32211cfa3c0e956564",
    strip_prefix = "protobuf-3.11.4",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.11.4.zip"],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

http_archive(
    name = "com_github_bazelbuild_buildtools",
    strip_prefix = "buildtools-master",
    url = "https://github.com/bazelbuild/buildtools/archive/2.2.1.zip",
)

load("//:tool_deps.bzl", "tool_deps")

tool_deps()

# gazelle:repository_macro go_deps.bzl%go_deps
load("//:go_deps.bzl", "go_deps")

go_deps()
