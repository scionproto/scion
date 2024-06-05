load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def buf_dependencies():
    http_archive(
        name = "buf",
        build_file_content = "exports_files([\"buf\"])",
        sha256 = "16253b6702dd447ef941b01c9c386a2ab7c8d20bbbc86a5efa5953270f6c9010",
        strip_prefix = "buf/bin",
        urls = ["https://github.com/bufbuild/buf/releases/download/v1.32.2/buf-Linux-x86_64.tar.gz"],
    )
