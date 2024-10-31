workspace(
    name = "com_github_scionproto_scion",
)

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

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

http_archive(
    name = "aspect_bazel_lib",
    sha256 = "714cf8ce95a198bab0a6a3adaffea99e929d2f01bf6d4a59a2e6d6af72b4818c",
    strip_prefix = "bazel-lib-2.7.8",
    url = "https://github.com/aspect-build/bazel-lib/releases/download/v2.7.8/bazel-lib-v2.7.8.tar.gz",
)

load("@aspect_bazel_lib//lib:repositories.bzl", "aspect_bazel_lib_dependencies", "aspect_bazel_lib_register_toolchains")

# Required bazel-lib dependencies

aspect_bazel_lib_dependencies()

# Register bazel-lib toolchains

aspect_bazel_lib_register_toolchains()

# Bazel rules for Golang
http_archive(
    name = "io_bazel_rules_go",
    patch_args = ["-p0"],
    patches = ["//patches:io_bazel_rules_go/import.patch"],
    sha256 = "af47f30e9cbd70ae34e49866e201b3f77069abb111183f2c0297e7e74ba6bbc0",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.47.0/rules_go-v0.47.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.47.0/rules_go-v0.47.0.zip",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

go_register_toolchains(
    nogo = "@//:nogo",
    version = "1.22.7",
)

# Gazelle
http_archive(
    name = "bazel_gazelle",
    sha256 = "d3fa66a39028e97d76f9e2db8f1b0c11c099e8e01bf363a923074784e451f809",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.33.0/bazel-gazelle-v0.33.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.33.0/bazel-gazelle-v0.33.0.tar.gz",
    ],
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")
load("//:tool_deps.bzl", "tool_deps")

tool_deps()

# gazelle:repository_macro go_deps.bzl%go_deps
load("//:go_deps.bzl", "go_deps")

go_deps()

gazelle_dependencies()

# Python rules
http_archive(
    name = "rules_python",
    sha256 = "9d04041ac92a0985e344235f5d946f71ac543f1b1565f2cdbc9a2aaee8adf55b",
    strip_prefix = "rules_python-0.26.0",
    url = "https://github.com/bazelbuild/rules_python/releases/download/0.26.0/rules_python-0.26.0.tar.gz",
)

load("@rules_python//python:repositories.bzl", "py_repositories", "python_register_toolchains")

py_repositories()

python_register_toolchains(
    name = "python3_10",
    python_version = "3.10",
)

load("@python3_10//:defs.bzl", python_interpreter = "interpreter")
load("//tools/env/pip3:deps.bzl", "python_deps")

python_deps(python_interpreter)

load("@com_github_scionproto_scion_python_deps//:requirements.bzl", install_python_deps = "install_deps")

install_python_deps()

load("//doc:deps.bzl", "python_doc_deps")

python_doc_deps(python_interpreter)

load("@com_github_scionproto_scion_python_doc_deps//:requirements.bzl", install_python_doc_deps = "install_deps")

install_python_doc_deps()

http_archive(
    name = "rules_pkg",
    patch_args = ["-p1"],
    patches = ["@//dist:rpm/rpm_rules.patch"],
    sha256 = "d250924a2ecc5176808fc4c25d5cf5e9e79e6346d79d5ab1c493e289e722d1d0",
    urls = [
        "https://github.com/bazelbuild/rules_pkg/releases/download/0.10.1/rules_pkg-0.10.1.tar.gz",
    ],
)

load("@rules_pkg//:deps.bzl", "rules_pkg_dependencies")

rules_pkg_dependencies()

# Antlr rules
http_archive(
    name = "rules_antlr",
    # XXX(roosd): This hash is not guaranteed to be stable by GitHub.
    # See: https://github.blog/changelog/2023-01-30-git-archive-checksums-may-change
    sha256 = "a9b2f98aae1fb26e9608be1e975587e6271a3287e424ced28cbc77f32190ec41",
    strip_prefix = "rules_antlr-0.6.1",
    urls = ["https://github.com/bacek/rules_antlr/archive/refs/tags/0.6.1.tar.gz"],
)

load("@rules_antlr//antlr:repositories.bzl", "rules_antlr_dependencies")

rules_antlr_dependencies("4.13.1")

# Rules for container image building
http_archive(
    name = "rules_oci",
    sha256 = "4a276e9566c03491649eef63f27c2816cc222f41ccdebd97d2c5159e84917c3b",
    strip_prefix = "rules_oci-1.7.4",
    url = "https://github.com/bazel-contrib/rules_oci/releases/download/v1.7.4/rules_oci-v1.7.4.tar.gz",
)

load("@rules_oci//oci:dependencies.bzl", "rules_oci_dependencies")

rules_oci_dependencies()

load("@rules_oci//oci:repositories.bzl", "LATEST_CRANE_VERSION", "oci_register_toolchains")

oci_register_toolchains(
    name = "oci",
    crane_version = LATEST_CRANE_VERSION,
)

load("@rules_oci//oci:pull.bzl", "oci_pull")

oci_pull(
    name = "distroless_base_debian10",
    digest = "sha256:72d496b69d121960b98ac7078cbacd7678f1941844b90b5e1cac337b91309d9d",
    registry = "gcr.io",
    repository = "distroless/base-debian10",
)

oci_pull(
    name = "debian10",
    digest = "sha256:60cb30babcd1740309903c37d3d408407d190cf73015aeddec9086ef3f393a5d",
    registry = "index.docker.io",
    repository = "library/debian",
)

# Debian packaging
http_archive(
    name = "rules_debian_packages",
    sha256 = "0ae3b332f9d894e57693ce900769d2bd1b693e1f5ea1d9cdd82fa4479c93bcc8",
    strip_prefix = "rules_debian_packages-0.2.0",
    url = "https://github.com/bazel-contrib/rules_debian_packages/releases/download/v0.2.0/rules_debian_packages-v0.2.0.tar.gz",
)

load("@rules_debian_packages//debian_packages:repositories.bzl", "rules_debian_packages_dependencies")

rules_debian_packages_dependencies(python_interpreter_target = python_interpreter)

load("@rules_debian_packages//debian_packages:defs.bzl", "debian_packages_repository")

debian_packages_repository(
    name = "tester_debian10_packages",
    default_arch = "amd64",
    default_distro = "debian10",
    lock_file = "//docker:tester_packages.lock",
)

load("@tester_debian10_packages//:packages.bzl", tester_debian_packages_install_deps = "install_deps")

tester_debian_packages_install_deps()

# RPM packaging
load("@rules_pkg//toolchains/rpm:rpmbuild_configure.bzl", "find_system_rpmbuild")

find_system_rpmbuild(
    name = "rules_pkg_rpmbuild",
    verbose = False,
)

# Buf CLI
http_archive(
    name = "buf",
    build_file_content = "exports_files([\"buf\"])",
    sha256 = "16253b6702dd447ef941b01c9c386a2ab7c8d20bbbc86a5efa5953270f6c9010",
    strip_prefix = "buf/bin",
    urls = ["https://github.com/bufbuild/buf/releases/download/v1.32.2/buf-Linux-x86_64.tar.gz"],
)

# protobuf/gRPC
http_archive(
    name = "rules_proto_grpc",
    sha256 = "9ba7299c5eb6ec45b6b9a0ceb9916d0ab96789ac8218269322f0124c0c0d24e2",
    strip_prefix = "rules_proto_grpc-4.5.0",
    urls = ["https://github.com/rules-proto-grpc/rules_proto_grpc/releases/download/4.5.0/rules_proto_grpc-4.5.0.tar.gz"],
)

load("@rules_proto_grpc//:repositories.bzl", "rules_proto_grpc_repos", "rules_proto_grpc_toolchains")

rules_proto_grpc_toolchains()

rules_proto_grpc_repos()

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")

rules_proto_dependencies()

rules_proto_toolchains()

load("@rules_proto_grpc//buf:repositories.bzl", rules_proto_grpc_buf_repos = "buf_repos")

rules_proto_grpc_buf_repos()

http_archive(
    name = "com_github_bazelbuild_buildtools",
    strip_prefix = "buildtools-6.3.3",
    urls = [
        "https://github.com/bazelbuild/buildtools/archive/refs/tags/6.3.3.tar.gz",
    ],
)

load("//tools/lint/python:deps.bzl", "python_lint_deps")

python_lint_deps(python_interpreter)

load("@com_github_scionproto_scion_python_lint_deps//:requirements.bzl", install_python_lint_deps = "install_deps")

install_python_lint_deps()

http_archive(
    name = "aspect_rules_js",
    sha256 = "a723815986f3dd8b2c58d0ea76fde0ed56eed65de3212df712e631e5fc7d8790",
    strip_prefix = "rules_js-2.0.0-rc6",
    url = "https://github.com/aspect-build/rules_js/releases/download/v2.0.0-rc6/rules_js-v2.0.0-rc6.tar.gz",
)

load("@aspect_rules_js//js:repositories.bzl", "rules_js_dependencies")

rules_js_dependencies()

load("@rules_nodejs//nodejs:repositories.bzl", "nodejs_register_toolchains")

nodejs_register_toolchains(
    name = "nodejs",
    node_version = "16.19.0",  # use DEFAULT_NODE_VERSION from previous version rules_nodejs; the current version links against too new glibc
)

load("@aspect_rules_js//npm:repositories.bzl", "npm_translate_lock")

npm_translate_lock(
    name = "npm",
    pnpm_lock = "@com_github_scionproto_scion//private/mgmtapi/tools:pnpm-lock.yaml",
    pnpm_version = "9.4.0",
    verify_node_modules_ignored = "@com_github_scionproto_scion//:.bazelignore",
)

load("@npm//:repositories.bzl", "npm_repositories")

npm_repositories()

# Support cross building and packaging for openwrt_amd64 via the openwrt SDK
http_archive(
    name = "openwrt_x86_64_SDK",
    build_file = "@//dist/openwrt:BUILD.external.bazel",
    patch_args = ["-p1"],
    patches = ["@//dist/openwrt:endian_h.patch"],
    sha256 = "df9cbce6054e6bd46fcf28e2ddd53c728ceef6cb27d1d7fc54a228f272c945b0",
    strip_prefix = "openwrt-sdk-23.05.2-x86-64_gcc-12.3.0_musl.Linux-x86_64",
    urls = ["https://downloads.openwrt.org/releases/23.05.2/targets/x86/64/openwrt-sdk-23.05.2-x86-64_gcc-12.3.0_musl.Linux-x86_64.tar.xz"],
)

register_toolchains(
    "//dist/openwrt:x86_64_openwrt_toolchain",
)
