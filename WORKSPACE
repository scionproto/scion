# Generic stuff for dealing with repositories.
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

# Bazel rules for Golang
git_repository(
    name = "io_bazel_rules_go",
    remote = "https://github.com/bazelbuild/rules_go.git",
    tag = "v0.20.2",
)

load("@io_bazel_rules_go//go:deps.bzl", "go_download_sdk", "go_rules_dependencies", "go_register_toolchains")

go_rules_dependencies()

go_download_sdk(
    name = "go_sdk",
    sdks = {
        "linux_amd64": ("go1.13.4.linux-amd64.tar.gz", "692d17071736f74be04a72a06dab9cac1cd759377bd85316e52b2227604c004c"),
    },
)

go_register_toolchains(nogo = "@//:nogo")

# Gazelle
http_archive(
    name = "bazel_gazelle",
    urls = [
        "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/bazel-gazelle/releases/download/v0.19.0/bazel-gazelle-v0.19.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.19.0/bazel-gazelle-v0.19.0.tar.gz",
    ],
    sha256 = "41bff2a0b32b02f20c227d234aa25ef3783998e5453f7eade929704dcff7cd4b",
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

gazelle_dependencies()

# Docker rules
http_archive(
    name = "io_bazel_rules_docker",
    sha256 = "14ac30773fdb393ddec90e158c9ec7ebb3f8a4fd533ec2abbfd8789ad81a284b",
    strip_prefix = "rules_docker-0.12.1",
    urls = ["https://github.com/bazelbuild/rules_docker/releases/download/v0.12.1/rules_docker-v0.12.1.tar.gz"],
)
load("@io_bazel_rules_docker//repositories:repositories.bzl", container_repositories = "repositories")

container_repositories()

load("@io_bazel_rules_docker//repositories:deps.bzl", container_deps = "deps")

container_deps()

# Distroless
git_repository(
    name = "distroless",
    commit = "07399042ca65818d19aa0a2b0325716e237c4d01",
    remote = "https://github.com/GoogleContainerTools/distroless.git",
)

# Debian packages to install in containers
load("@distroless//package_manager:package_manager.bzl", "package_manager_repositories")
load("@distroless//package_manager:dpkg.bzl", "dpkg_src", "dpkg_list")

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
git_repository(
    name = "com_google_protobuf",
    commit = "09745575a923640154bcf307fba8aedff47f240a",
    remote = "https://github.com/protocolbuffers/protobuf",
    shallow_since = "1558721209 -0700",
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

load("//:tool_deps.bzl", "tool_deps")

tool_deps()

# gazelle:repository_macro go_deps.bzl%go_deps
load("//:go_deps.bzl", "go_deps")

go_deps()
