load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def rules_openapi_dependencies():
    maybe(
        http_archive,
        name = "build_bazel_rules_nodejs",
        sha256 = "b32a4713b45095e9e1921a7fcb1adf584bc05959f3336e7351bcf77f015a2d7c",
        urls = ["https://github.com/bazelbuild/rules_nodejs/releases/download/4.1.0/rules_nodejs-4.1.0.tar.gz"],
    )

    maybe(
        http_archive,
        name = "cgrindel_rules_updatesrc",
        sha256 = "18eb6620ac4684c2bc722b8fe447dfaba76f73d73e2dfcaf837f542379ed9bc3",
        strip_prefix = "rules_updatesrc-0.1.0",
        urls = ["https://github.com/cgrindel/rules_updatesrc/archive/v0.1.0.tar.gz"],
        patches = ["@com_github_scionproto_scion//rules_openapi:rules_updatesrc.patch"],
        patch_args = ["-p1"],
    )
