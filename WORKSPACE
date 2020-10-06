# Generic stuff for dealing with repositories.
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

# Bazel rules for Golang
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "2697f6bc7c529ee5e6a2d9799870b9ec9eaeb3ee7d70ed50b87a2c2c97e13d9e",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.23.8/rules_go-v0.23.8.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.23.8/rules_go-v0.23.8.tar.gz",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_download_sdk", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

go_download_sdk(
    name = "go_sdk",
    sdks = {
        "linux_amd64": ("go1.14.9.linux-amd64.tar.gz", "f0d26ff572c72c9823ae752d3c81819a81a60c753201f51f89637482531c110a"),
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
load("//:tool_deps.bzl", "tool_deps")

tool_deps()

# gazelle:repository_macro go_deps.bzl%go_deps
load("//:go_deps.bzl", "go_deps")

go_deps()

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
    sha256 = "aeca78988341a2ee1ba097641056d168320ecc51372ef7ff8e64b139516a4937",
    urls = [
        "https://github.com/bazelbuild/rules_pkg/releases/download/0.2.6-1/rules_pkg-0.2.6.tar.gz",
        "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/0.2.6/rules_pkg-0.2.6.tar.gz",
    ],
)

load("@rules_pkg//:deps.bzl", "rules_pkg_dependencies")

rules_pkg_dependencies()

# Docker rules
http_archive(
    name = "io_bazel_rules_docker",
    sha256 = "4521794f0fba2e20f3bf15846ab5e01d5332e587e9ce81629c7f96c793bb7036",
    strip_prefix = "rules_docker-0.14.4",
    urls = ["https://github.com/bazelbuild/rules_docker/releases/download/v0.14.4/rules_docker-v0.14.4.tar.gz"],
)

load("@io_bazel_rules_docker//repositories:repositories.bzl", container_repositories = "repositories")

container_repositories()

load("@io_bazel_rules_docker//repositories:deps.bzl", container_deps = "deps")

container_deps()

load("@io_bazel_rules_docker//repositories:pip_repositories.bzl", docker_pip_deps = "pip_deps")

docker_pip_deps()

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
    name = "debian10",
    arch = "amd64",
    distro = "buster",
    sha256 = "f251129edc5e5b31dadd7bb252e5ce88b3fdbd76de672bc0bbcda4f667d5f47f",
    snapshot = "20200612T083553Z",
    url = "https://snapshot.debian.org/archive",
)

dpkg_src(
    name = "debian10_updates",
    arch = "amd64",
    distro = "buster-updates",
    sha256 = "24b35fcd184d71f83c3f553a72e6636954552331adfbbc694f0f70bd33e1a2b4",
    snapshot = "20200612T083553Z",
    url = "https://snapshot.debian.org/archive",
)

dpkg_src(
    name = "debian10_security",
    package_prefix = "https://snapshot.debian.org/archive/debian-security/20200612T105246Z/",
    packages_gz_url = "https://snapshot.debian.org/archive/debian-security/20200612T105246Z/dists/buster/updates/main/binary-amd64/Packages.gz",
    sha256 = "c0ae35609f2d445e73ca8d3c03dc843f5ddae50f474cee10e79c4c1284ce2a2d",
)

dpkg_list(
    name = "packages_debian10",
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
        "libcap2",
        "libcap2-bin",
        "libidn2-0",
        "libunistring2",
        "libnettle6",
        # iproute2 and its dependencies
        "iproute2",
        "libelf1",
        "libmnl0",
    ],
    # From Distroless WORKSPACE:
    # Takes the first package found: security updates should go first
    # If there was a security fix to a package before the stable release, this will find
    # the older security release. This happened for stretch libc6.
    sources = [
        "@debian10_security//file:Packages.json",
        "@debian10_updates//file:Packages.json",
        "@debian10//file:Packages.json",
    ],
)

load("@io_bazel_rules_docker//container:container.bzl", "container_pull")

container_pull(
    name = "static_debian10",
    digest = "sha256:4433370ec2b3b97b338674b4de5ffaef8ce5a38d1c9c0cb82403304b8718cde9",
    registry = "gcr.io",
    repository = "distroless/static-debian10",
)

container_pull(
    name = "debug_debian10",
    digest = "sha256:72d496b69d121960b98ac7078cbacd7678f1941844b90b5e1cac337b91309d9d",
    registry = "gcr.io",
    repository = "distroless/base-debian10",
)

container_pull(
    name = "ubuntu16",
    digest = "sha256:a98d9dcf3a34b2b78e78c61d003eb4d7a90d30fd54451686e2f0bd2ef5f602ac",
    registry = "index.docker.io",
    repository = "library/ubuntu",
    tag = "16.04",
)

container_pull(
    name = "node_slim",
    digest = "sha256:1e33616579a5d5de9ec0a861798fb45602a1332be32a67a1cb227b667a5a4d63",
    registry = "index.docker.io",
    repository = "library/node",
    tag = "10.16-slim",
)

# Busybox (used in debug docker images)
http_file(
    name = "busybox",
    executable = True,
    sha256 = "b51b9328eb4e60748912e1c1867954a5cf7e9d5294781cae59ce225ed110523c",
    urls = [
        "https://busybox.net/downloads/binaries/1.27.1-i686/busybox",
        "https://drive.google.com/uc?id=1RqCvs8CJubqzHYwJO5MI9UqPixMModWX",
    ],
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

go_repository(
    name = "com_github_jmhodges_bazel_gomock",
    importpath = "github.com/jmhodges/bazel_gomock",
    sum = "h1:eumRMfjSqbydOAh1rCp/MhtNRBP+GcOJ81IhBVTHAQc=",
    version = "v0.0.0-20200110073353-ed0530bf40e4",
)

http_file(
    name = "buf_bin",
    downloaded_file_path = "buf",
    executable = True,
    sha256 = "5faf15ed0a3cd4bd0919ba5fcb95334c1fd2ba32770df289d615138fa188d36a",
    urls = [
        "https://github.com/bufbuild/buf/releases/download/v0.20.5/buf-Linux-x86_64",
    ],
)

load("//:dlv_deps.bzl", "dlv_repositories")

# gazelle:repository_macro dlv_deps.bzl%dlv_repositories
dlv_repositories()
