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
        name = "cgrindel_bazel_starlib",
        sha256 = "163a45d949fdb96b328bb44fe56976c610c6728c77118c6cd999f26cedca97eb",
        strip_prefix = "bazel-starlib-0.2.1",
        urls = [
            "http://github.com/cgrindel/bazel-starlib/archive/v0.2.1.tar.gz",
        ],
        patches = ["@com_github_scionproto_scion//rules_openapi:rules_starlib.patch"],
        patch_args = ["-p1"],
    )
