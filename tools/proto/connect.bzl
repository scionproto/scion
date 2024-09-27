load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
load("//tools/lint:write_source_files.bzl", "write_source_files")
load("@aspect_bazel_lib//lib:copy_to_directory.bzl", "copy_to_directory")
load("@aspect_bazel_lib//lib:directory_path.bzl", "make_directory_path")

def go_connect_library(name, proto, files = None):
    # See: https://github.com/bazelbuild/rules_go/issues/3658#issuecomment-1678046338

    go_proto_library(
        name = "go_default_library",
        compilers = [
            "//tools/proto:connect_go_proto_compiler",
        ],
        importpath = "github.com/scionproto/scion/pkg/proto/" + proto,
        overrideimportpath = "github.com/scionproto/scion/pkg/proto/%s/v1/%sconnect" % (proto, proto),
        proto = "//proto/%s/v1:%s" % (proto, proto),
        visibility = ["//visibility:public"],
        deps = ["//pkg/proto/%s:go_default_library" % proto],
    )

    file_target = "go_default_library.filegroup"
    dir_target = "go_default_library.directory"

    native.filegroup(
        name = file_target,
        srcs = [":go_default_library"],
        output_group = "go_generated_srcs",
    )

    copy_to_directory(
        name = dir_target,
        srcs = [file_target],
        root_paths = ["**"],
    )

    if not files:
        files = ["%s.connect.go" % proto]

    write_source_files(
        name = "write_files",
        files = {
            output_file: make_directory_path("_{}_dirpath".format(output_file), dir_target, output_file)
            for output_file in files
        },
    )
