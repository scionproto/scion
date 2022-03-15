load("@io_bazel_rules_go//go:def.bzl", _go_embed_data = "go_embed_data")
load("@cgrindel_bazel_starlib//updatesrc:defs.bzl", "updatesrc_update")
load(":go_fmt.bzl", _go_fmt = "go_fmt")

def go_embed_data(
        name,
        srcs,
        flatten,
        var,
        out_src = "embedded.gen.go",
        *kwargs):
    _go_embed_data(
        name = name,
        srcs = srcs,
        flatten = flatten,
        var = var,
        *kwargs
    )

    fmt_name = name + "-fmt"
    _go_fmt(
        name = fmt_name,
        src = ":" + name,
    )

    updatesrc_update(
        name = name + "-update",
        srcs = [out_src],
        outs = [":" + fmt_name],
    )
