"""Module extension for non-module dependencies."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def _non_module_deps_impl(
        # buildifier: disable=unused-variable
        mctx):
    # TODO(bazelbuild/buildtools#1204): Remove when available as module.
    http_archive(
        name = "com_github_bazelbuild_buildtools",
        sha256 = "0063f317e135481783f3dc14c82bc15e0bf873c5e9aeece63b4f94d151aeb09f",
        strip_prefix = "buildtools-8.0.2",
        urls = ["https://github.com/bazelbuild/buildtools/archive/v8.0.2.tar.gz"],
    )
    http_archive(
        name = "rules_antlr",
        # XXX(roosd): This hash is not guaranteed to be stable by GitHub.
        # See: https://github.blog/changelog/2023-01-30-git-archive-checksums-may-change
        sha256 = "a9b2f98aae1fb26e9608be1e975587e6271a3287e424ced28cbc77f32190ec41",
        strip_prefix = "rules_antlr-0.6.1",
        urls = ["https://github.com/bacek/rules_antlr/archive/refs/tags/0.6.1.tar.gz"],
    )
    http_archive(
        name = "openwrt_x86_64_SDK",
        build_file = "@//dist/openwrt:BUILD.external.bazel",
        patch_args = ["-p1"],
        patches = ["@//dist/openwrt:endian_h.patch"],
        sha256 = "df9cbce6054e6bd46fcf28e2ddd53c728ceef6cb27d1d7fc54a228f272c945b0",
        strip_prefix = "openwrt-sdk-23.05.2-x86-64_gcc-12.3.0_musl.Linux-x86_64",
        urls = ["https://downloads.openwrt.org/releases/23.05.2/targets/x86/64/openwrt-sdk-23.05.2-x86-64_gcc-12.3.0_musl.Linux-x86_64.tar.xz"],
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
