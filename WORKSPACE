workspace(name = "com_github_scionproto_scion")

# Generic stuff for dealing with repositories.
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
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
    sha256 = "69de5c704a05ff37862f7e0f5534d4f479418afc21806c887db544a316f3cb6b",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.27.0/rules_go-v0.27.0.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.27.0/rules_go-v0.27.0.tar.gz",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_register_toolchains(
    nogo = "@//:nogo",
    version = "1.16.6",
)

# Gazelle
http_archive(
    name = "bazel_gazelle",
    sha256 = "62ca106be173579c0a167deb23358fdfe71ffa1e4cfdddf5582af26520f1c66f",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.23.0/bazel-gazelle-v0.23.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.23.0/bazel-gazelle-v0.23.0.tar.gz",
    ],
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")
load("//:tool_deps.bzl", "tool_deps")

# override dependency version set in go_rules_dependencies.
# See https://github.com/bazelbuild/rules_go/blob/master/go/dependencies.rst#overriding-dependencies.
go_repository(
    name = "org_golang_x_sys",
    importpath = "golang.org/x/sys",
    sum = "h1:gG67DSER+11cZvqIMb8S8bt0vZtiN6xWYARwirrOSfE=",
    version = "v0.0.0-20210510120138-977fb7262007",
)

go_rules_dependencies()

tool_deps()

# gazelle:repository_macro go_deps.bzl%go_deps
load("//:go_deps.bzl", "go_deps")

go_deps()

gazelle_dependencies()

# XXX Needs to be before rules_docker
# Python rules
http_archive(
    name = "rules_python",
    sha256 = "4feecd37ec6e9941a455a19e7392bed65003eab0aa6ea347ca431bce2640e530",
    strip_prefix = "rules_python-0.3.0",
    url = "https://github.com/bazelbuild/rules_python/archive/0.3.0.tar.gz",
)

load("@rules_python//python:pip.bzl", "pip_install")

pip_install(
    name = "pip3_deps",
    requirements = "//env/pip3:requirements.txt",
)

http_archive(
    name = "rules_pkg",
    sha256 = "038f1caa773a7e35b3663865ffb003169c6a71dc995e39bf4815792f385d837d",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/0.4.0/rules_pkg-0.4.0.tar.gz",
        "https://github.com/bazelbuild/rules_pkg/releases/download/0.4.0/rules_pkg-0.4.0.tar.gz",
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
    sha256 = "59d5b42ac315e7eadffa944e86e90c2990110a1c8075f1cd145f487e999d22b3",
    strip_prefix = "rules_docker-0.17.0",
    urls = ["https://github.com/bazelbuild/rules_docker/releases/download/v0.17.0/rules_docker-v0.17.0.tar.gz"],
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

http_archive(
    name = "com_github_jmhodges_bazel_gomock",
    sha256 = "2da16771642ce7f75a8d620a1029b83ee29b206c6665bb8c92f003b427e35dbf",
    strip_prefix = "bazel_gomock-4f2ee840432b1a08ccc46ee4f2c1f5a2bad8fade",
    urls = [
        "https://github.com/jmhodges/bazel_gomock/archive/4f2ee840432b1a08ccc46ee4f2c1f5a2bad8fade.tar.gz",
    ],
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
