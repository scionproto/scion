"""Module extension for non-module dependencies."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def _non_module_deps_impl(
        # buildifier: disable=unused-variable
        mctx):
    # TODO: Remove when available as module.
    http_archive(
        name = "com_github_bazelbuild_buildtools",
        sha256 = "573345c2039889a4001b9933a7ebde8dcaf910c47787993aecccebc3117a4425",
        strip_prefix = "buildtools-8.0.3",
        urls = ["https://github.com/bazelbuild/buildtools/archive/v8.0.3.tar.gz"],
    )

    # Buf CLI
    http_archive(
        name = "buf",
        build_file_content = "exports_files([\"buf\"])",
        sha256 = "16253b6702dd447ef941b01c9c386a2ab7c8d20bbbc86a5efa5953270f6c9010",
        strip_prefix = "buf/bin",
        urls = ["https://github.com/bufbuild/buf/releases/download/v1.32.2/buf-Linux-x86_64.tar.gz"],
    )

non_module_deps = module_extension(
    implementation = _non_module_deps_impl,
)
