workspace(
    name = "com_github_scionproto_scion",
    managed_directories = {
        "@rules_openapi_npm": ["rules_openapi/tools/node_modules"],
    },
)

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

# linter rules
http_archive(
    name = "apple_rules_lint",
    sha256 = "8feab4b08a958b10cb2abb7f516652cd770b582b36af6477884b3bba1f2f0726",
    strip_prefix = "apple_rules_lint-0.1.1",
    urls = [
        "https://github.com/apple/apple_rules_lint/archive/0.1.1.zip",
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
    sha256 = "16e9fca53ed6bd4ff4ad76facc9b7b651a89db1689a2877d6fd7b82aa824e366",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.34.0/rules_go-v0.34.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.34.0/rules_go-v0.34.0.zip",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_register_toolchains(
    nogo = "@//:nogo",
    version = "1.19.2",
)

# Gazelle
http_archive(
    name = "bazel_gazelle",
    patch_args = ["-p1"],
    patches = [
        # PR: https://github.com/bazelbuild/bazel-gazelle/pull/1243
        "@//patches/bazel_gazelle:gazelle.patch",
    ],
    sha256 = "501deb3d5695ab658e82f6f6f549ba681ea3ca2a5fb7911154b5aa45596183fa",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.26.0/bazel-gazelle-v0.26.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.26.0/bazel-gazelle-v0.26.0.tar.gz",
    ],
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

go_rules_dependencies()

load("//:tool_deps.bzl", "tool_deps")

tool_deps()

# gazelle:repository_macro go_deps.bzl%go_deps
load("//:go_deps.bzl", "go_deps")

go_deps()

## Explictly override xerrors: https://github.com/bazelbuild/bazel-gazelle/issues/1217
go_repository(
    name = "org_golang_x_xerrors",
    importpath = "golang.org/x/xerrors",
    sum = "h1:go1bK/D/BFZV2I8cIQd1NKEZ+0owSTG1fDTci4IqFcE=",
    version = "v0.0.0-20200804184101-5ec99f83aff1",
)

gazelle_dependencies()

# XXX Needs to be before rules_docker
# Python rules
http_archive(
    name = "rules_python",
    sha256 = "8c8fe44ef0a9afc256d1e75ad5f448bb59b81aba149b8958f02f7b3a98f5d9b4",
    strip_prefix = "rules_python-0.13.0",
    url = "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.13.0.tar.gz",
)

load("@rules_python//python:repositories.bzl", "python_register_toolchains")

python_register_toolchains(
    name = "python3_10",
    python_version = "3.10",
)

load("@python3_10//:defs.bzl", "interpreter")
load("//tools/env/pip3:deps.bzl", "python_deps")

python_deps(interpreter)

load("@com_github_scionproto_scion_python_deps//:requirements.bzl", install_python_deps = "install_deps")

install_python_deps()

http_archive(
    name = "rules_pkg",
    sha256 = "62eeb544ff1ef41d786e329e1536c1d541bb9bcad27ae984d57f18f314018e66",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/0.6.0/rules_pkg-0.6.0.tar.gz",
        "https://github.com/bazelbuild/rules_pkg/releases/download/0.6.0/rules_pkg-0.6.0.tar.gz",
    ],
)

load("@rules_pkg//:deps.bzl", "rules_pkg_dependencies")

rules_pkg_dependencies()

# Antlr rules
http_archive(
    name = "rules_antlr",
    sha256 = "234c401cfabab78f2d7f5589239d98f16f04338768a72888f660831964948ab1",
    strip_prefix = "rules_antlr-0.6.0",
    urls = ["https://github.com/artisoft-io/rules_antlr/archive/0.6.0.tar.gz"],
)

load("@rules_antlr//antlr:repositories.bzl", "rules_antlr_dependencies")

rules_antlr_dependencies("4.9.3")

http_archive(
    name = "io_bazel_rules_docker",
    sha256 = "85ffff62a4c22a74dbd98d05da6cf40f497344b3dbf1e1ab0a37ab2a1a6ca014",
    strip_prefix = "rules_docker-0.23.0",
    urls = ["https://github.com/bazelbuild/rules_docker/releases/download/v0.23.0/rules_docker-v0.23.0.tar.gz"],
)

load("@io_bazel_rules_docker//repositories:repositories.bzl", container_repositories = "repositories")

container_repositories()

load("@io_bazel_rules_docker//repositories:deps.bzl", container_deps = "deps")

container_deps()

load("@io_bazel_rules_docker//go:image.bzl", _go_image_repos = "repositories")

_go_image_repos()

http_archive(
    name = "rules_deb_packages",
    sha256 = "674ce7b66c345aaa9ab898608618a0a0db857cbed8e8d0794ca46e375fd5ff76",
    urls = ["https://github.com/petermylemans/rules_deb_packages/releases/download/v0.4.0/rules_deb_packages.tar.gz"],
)

load("@rules_deb_packages//:repositories.bzl", "deb_packages_dependencies")

deb_packages_dependencies()

load("@rules_deb_packages//:deb_packages.bzl", "deb_packages")

deb_packages(
    name = "debian_buster_amd64",
    arch = "amd64",
    packages = {
        "libc6": "pool/main/g/glibc/libc6_2.28-10_amd64.deb",
        "libcap2": "pool/main/libc/libcap2/libcap2_2.25-2_amd64.deb",
        "libcap2-bin": "pool/main/libc/libcap2/libcap2-bin_2.25-2_amd64.deb",
    },
    packages_sha256 = {
        "libc6": "6f703e27185f594f8633159d00180ea1df12d84f152261b6e88af75667195a79",
        "libcap2": "8f93459c99e9143dfb458353336c5171276860896fd3e10060a515cd3ea3987b",
        "libcap2-bin": "3c8c5b1410447356125fd8f5af36d0c28853b97c072037af4a1250421008b781",
    },
    sources = [
        "http://deb.debian.org/debian buster main",
        "http://deb.debian.org/debian buster-updates main",
        "http://deb.debian.org/debian-security buster/updates main",
    ],
    timestamp = "20210812T060609Z",
    urls = [
        "http://deb.debian.org/debian/$(package_path)",
        "http://deb.debian.org/debian-security/$(package_path)",
        "https://snapshot.debian.org/archive/debian/$(timestamp)/$(package_path)",  # Needed in case of supersed archive no more available on the mirrors
        "https://snapshot.debian.org/archive/debian-security/$(timestamp)/$(package_path)",  # Needed in case of supersed archive no more available on the mirrors
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

# protobuf/gRPC
http_archive(
    name = "rules_proto_grpc",
    sha256 = "7954abbb6898830cd10ac9714fbcacf092299fda00ed2baf781172f545120419",
    strip_prefix = "rules_proto_grpc-3.1.1",
    urls = ["https://github.com/rules-proto-grpc/rules_proto_grpc/archive/3.1.1.tar.gz"],
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

http_file(
    name = "buf_bin",
    downloaded_file_path = "buf",
    executable = True,
    sha256 = "5faf15ed0a3cd4bd0919ba5fcb95334c1fd2ba32770df289d615138fa188d36a",
    urls = [
        "https://github.com/bufbuild/buf/releases/download/v0.20.5/buf-Linux-x86_64",
    ],
)

load("//tools/lint/python:deps.bzl", "python_lint_deps")

python_lint_deps(interpreter)

load("@com_github_scionproto_scion_python_lint_deps//:requirements.bzl", install_python_lint_deps = "install_deps")

install_python_lint_deps()

load("//rules_openapi:dependencies.bzl", "rules_openapi_dependencies")

rules_openapi_dependencies()

load("//rules_openapi:install.bzl", "rules_openapi_install_yarn_dependencies")

rules_openapi_install_yarn_dependencies()

# TODO(lukedirtwalker): can that be integrated in the rules_openapi_dependencies
# call above somehow?
load("@cgrindel_bazel_starlib//:deps.bzl", "bazel_starlib_dependencies")

bazel_starlib_dependencies()
