workspace(name = "com_github_scionproto_scion")

# Generic stuff for dealing with repositories.
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

# linter rules
http_archive(
    name = "apple_rules_lint",
    sha256 = "ece669d52998c7a0df2c2380f37edbf4ed8ebb1a03587ed1781dfbececef9b3d",
    urls = [
        "https://github.com/apple/apple_rules_lint/releases/download/0.1.0/apple_rules_lint-0.1.0.tar.gz",
    ],
)

load("@apple_rules_lint//lint:repositories.bzl", "lint_deps")

lint_deps()

load("@apple_rules_lint//lint:setup.bzl", "lint_setup")

# Add your linters here.
lint_setup({
    "go": "//:go_lint_config",
    "flake8": "//:flake8_lint_config",
})

# Bazel rules for Golang
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "6f111c57fd50baf5b8ee9d63024874dd2a014b069426156c55adbf6d3d22cb7b",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.25.0/rules_go-v0.25.0.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.25.0/rules_go-v0.25.0.tar.gz",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

go_register_toolchains(
    nogo = "@//:nogo",
    version = "1.15.6",
)

# Gazelle
http_archive(
    name = "bazel_gazelle",
    sha256 = "b85f48fa105c4403326e9525ad2b2cc437babaa6e15a3fc0b1dbab0ab064bc7c",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.22.2/bazel-gazelle-v0.22.2.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.22.2/bazel-gazelle-v0.22.2.tar.gz",
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
http_archive(
    name = "rules_python",
    sha256 = "48f7e716f4098b85296ad93f5a133baf712968c13fbc2fdf3a6136158fe86eac",
    strip_prefix = "rules_python-0.1.0",
    url = "https://github.com/bazelbuild/rules_python/archive/0.1.0.tar.gz",
)

load("@rules_python//python:repositories.bzl", "py_repositories")

py_repositories()

load("@rules_python//python:pip.bzl", "pip_install")

pip_install(
    name = "pip3_deps",
    requirements = "//env/pip3:requirements.txt",
)

http_archive(
    name = "rules_pkg",
    sha256 = "6b5969a7acd7b60c02f816773b06fcf32fbe8ba0c7919ccdc2df4f8fb923804a",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/0.3.0/rules_pkg-0.3.0.tar.gz",
        "https://github.com/bazelbuild/rules_pkg/releases/download/0.3.0/rules_pkg-0.3.0.tar.gz",
    ],
)

load("@rules_pkg//:deps.bzl", "rules_pkg_dependencies")

rules_pkg_dependencies()

# Antlr rules
http_archive(
    name = "rules_antlr",
    sha256 = "26e6a83c665cf6c1093b628b3a749071322f0f70305d12ede30909695ed85591",
    strip_prefix = "rules_antlr-0.5.0",
    urls = ["https://github.com/marcohu/rules_antlr/archive/0.5.0.tar.gz"],
)

load("@rules_antlr//antlr:repositories.bzl", "rules_antlr_dependencies")

rules_antlr_dependencies("4.7.2")

http_archive(
    name = "io_bazel_rules_docker",
    sha256 = "58636bf623c8ccd2c0d70a6b108619a2f07bc284ad270a6b21fb635d4dd1ecfc",
    strip_prefix = "rules_docker-6c29619903b6bc533ad91967f41f2a3448758e6f",
    urls = ["https://github.com/bazelbuild/rules_docker/archive/6c29619903b6bc533ad91967f41f2a3448758e6f.tar.gz"],
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
    name = "debian10_snap",
    arch = "amd64",
    distro = "buster",
    sha256 = "f251129edc5e5b31dadd7bb252e5ce88b3fdbd76de672bc0bbcda4f667d5f47f",
    snapshot = "20200612T083553Z",
    url = "https://snapshot.debian.org/archive",
)

dpkg_src(
    name = "debian10_updates_snap",
    arch = "amd64",
    distro = "buster-updates",
    sha256 = "24b35fcd184d71f83c3f553a72e6636954552331adfbbc694f0f70bd33e1a2b4",
    snapshot = "20200612T083553Z",
    url = "https://snapshot.debian.org/archive",
)

dpkg_src(
    name = "debian10_security_snap",
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
        # Needed to add network capabilities to apps.
        "libcap2",
        "libcap2-bin",
    ],
    # From Distroless WORKSPACE:
    # Takes the first package found: security updates should go first
    # If there was a security fix to a package before the stable release, this will find
    # the older security release. This happened for stretch libc6.
    sources = [
        "@debian10_security_snap//file:Packages.json",
        "@debian10_updates_snap//file:Packages.json",
        "@debian10_snap//file:Packages.json",
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
    name = "debian10",
    digest = "sha256:60cb30babcd1740309903c37d3d408407d190cf73015aeddec9086ef3f393a5d",
    registry = "index.docker.io",
    repository = "library/debian",
    tag = "10",
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

# protobuf/gRPC
http_archive(
    name = "rules_proto_grpc",
    sha256 = "d771584bbff98698e7cb3cb31c132ee206a972569f4dc8b65acbdd934d156b33",
    strip_prefix = "rules_proto_grpc-2.0.0",
    urls = ["https://github.com/rules-proto-grpc/rules_proto_grpc/archive/2.0.0.tar.gz"],
)

load("@rules_proto_grpc//:repositories.bzl", "rules_proto_grpc_repos", "rules_proto_grpc_toolchains")

rules_proto_grpc_toolchains()

rules_proto_grpc_repos()

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")

rules_proto_dependencies()

rules_proto_toolchains()

load("@rules_proto_grpc//python:repositories.bzl", rules_proto_grpc_python_repos = "python_repos")

rules_proto_grpc_python_repos()

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

grpc_deps()

http_archive(
    name = "com_github_bazelbuild_buildtools",
    strip_prefix = "buildtools-master",
    url = "https://github.com/bazelbuild/buildtools/archive/2.2.1.zip",
)

# TODO(lukedirtwalker): Use in-tree version for this.
# This commit is from https://github.com/jmhodges/bazel_gomock/pull/49
http_archive(
    name = "com_github_jmhodges_bazel_gomock",
    strip_prefix = "bazel_gomock-7e1f48084f0b833bfd1e607555b456639f24bb6e",
    url = "https://github.com/jmhodges/bazel_gomock/archive/7e1f48084f0b833bfd1e607555b456639f24bb6e.tar.gz",
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

load("//:bbcp.bzl", "bbcp_repository")

bbcp_repository()

load("//lint/private/python:deps.bzl", "python_lint_deps")

python_lint_deps()
