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
    sha256 = "aed1c249d4ec8f703edddf35cbe9dfaca0b5f5ea6e4cd9e83e99f3b0d1136c3d",
    strip_prefix = "rules_docker-0.7.0",
    urls = ["https://github.com/bazelbuild/rules_docker/archive/v0.7.0.tar.gz"],
)

load("@io_bazel_rules_docker//repositories:repositories.bzl", container_repositories = "repositories")

container_repositories()

# Distroless
git_repository(
    name = "distroless",
    commit = "0a3d642379d577a09225f1275e5c96e336472dfc",
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
    sha256 = "4cb2fac3e32292613b92d3162e99eb8a1ed7ce47d1b142852b0de3092b25910c",
    snapshot = "20180406T095535Z",
    url = "http://snapshot.debian.org/archive",
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
        "@debian_stretch//file:Packages.json",
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
