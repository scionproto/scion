"""Module extension for non-module dependencies."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def _non_module_deps_impl(ctx):
    http_archive(
        name = "rules_antlr",
        # XXX(roosd): This hash is not guaranteed to be stable by GitHub.
        # See: https://github.blog/changelog/2023-01-30-git-archive-checksums-may-change
        sha256 = "a9b2f98aae1fb26e9608be1e975587e6271a3287e424ced28cbc77f32190ec41",
        strip_prefix = "rules_antlr-0.6.1",
        urls = ["https://github.com/bacek/rules_antlr/archive/refs/tags/0.6.1.tar.gz"],
    )

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

non_module_deps = module_extension(
    implementation = _non_module_deps_impl,
)
