workspace(
    name = "com_github_scionproto_scion",
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

http_archive(
    name = "aspect_bazel_lib",
    sha256 = "a185ccff9c1b8589c63f66d7eb908de15c5d6bb05562be5f46336c53e7a7326a",
    strip_prefix = "bazel-lib-2.0.0-rc1",
    url = "https://github.com/aspect-build/bazel-lib/releases/download/v2.0.0-rc1/bazel-lib-v2.0.0-rc1.tar.gz",
)

load("@aspect_bazel_lib//lib:repositories.bzl", "aspect_bazel_lib_dependencies", "aspect_bazel_lib_register_toolchains")

# Required bazel-lib dependencies

aspect_bazel_lib_dependencies()

# Register bazel-lib toolchains

aspect_bazel_lib_register_toolchains()

# Bazel rules for Golang
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "91585017debb61982f7054c9688857a2ad1fd823fc3f9cb05048b0025c47d023",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.42.0/rules_go-v0.42.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.42.0/rules_go-v0.42.0.zip",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_register_toolchains(
    nogo = "@//:nogo",
    version = "1.21.10",
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

go_rules_dependencies()

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
    sha256 = "8f9ee2dc10c1ae514ee599a8b42ed99fa262b757058f65ad3c384289ff70c4b8",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/0.9.1/rules_pkg-0.9.1.tar.gz",
        "https://github.com/bazelbuild/rules_pkg/releases/download/0.9.1/rules_pkg-0.9.1.tar.gz",
    ],
)

load("@rules_pkg//:deps.bzl", "rules_pkg_dependencies")

rules_pkg_dependencies()

# Antlr rules
http_archive(
    name = "rules_antlr",
    # XXX(roosd): This hash is not guaranteed to be stable by GitHub.
    # See: https://github.blog/changelog/2023-01-30-git-archive-checksums-may-change
    sha256 = "8d7c457cc266965bdcf7e85aa349d2f851b772a55877354d9ae92ada7a62c857",
    strip_prefix = "rules_antlr-0.6.0",
    urls = ["https://github.com/bacek/rules_antlr/archive/refs/tags/0.6.0.tar.gz"],
)

load("@rules_antlr//antlr:repositories.bzl", "rules_antlr_dependencies")

rules_antlr_dependencies("4.9.3")

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

python_lint_deps(python_interpreter)

load("@com_github_scionproto_scion_python_lint_deps//:requirements.bzl", install_python_lint_deps = "install_deps")

install_python_lint_deps()

http_archive(
    name = "aspect_rules_js",
    sha256 = "a949d56fed8fa0a8dd82a0a660acc949253a05b2b0c52a07e4034e27f11218f6",
    strip_prefix = "rules_js-1.33.1",
    url = "https://github.com/aspect-build/rules_js/releases/download/v1.33.1/rules_js-v1.33.1.tar.gz",
)

load("@aspect_rules_js//js:repositories.bzl", "rules_js_dependencies")

rules_js_dependencies()

load("@rules_nodejs//nodejs:repositories.bzl", "DEFAULT_NODE_VERSION", "nodejs_register_toolchains")

nodejs_register_toolchains(
    name = "nodejs",
    node_version = DEFAULT_NODE_VERSION,
)

load("@aspect_rules_js//npm:npm_import.bzl", "npm_translate_lock")

npm_translate_lock(
    name = "npm",
    pnpm_lock = "@com_github_scionproto_scion//private/mgmtapi/tools:pnpm-lock.yaml",
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
