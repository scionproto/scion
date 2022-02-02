# This file was copied from https://github.com/cgrindel/rules_updatesrc/tree/main/examples/simple/header
load(
    "@cgrindel_bazel_starlib//updatesrc:defs.bzl",
    "UpdateSrcsInfo",
    "update_srcs",
)

def _header_impl(ctx):
    outs = []
    updsrcs = []
    for src in ctx.files.srcs:
        out = ctx.actions.declare_file(src.basename + "_with_header")
        outs.append(out)
        updsrcs.append(update_srcs.create(src = src, out = out))
        ctx.actions.run(
            outputs = [out],
            inputs = [src],
            executable = ctx.executable._header_tool,
            arguments = [src.path, out.path, ctx.attr.header],
        )

    return [
        DefaultInfo(files = depset(outs)),
        UpdateSrcsInfo(update_srcs = depset(updsrcs)),
    ]

header = rule(
    implementation = _header_impl,
    attrs = {
        "srcs": attr.label_list(
            allow_files = True,
            mandatory = True,
        ),
        "header": attr.string(
            mandatory = True,
        ),
        "_header_tool": attr.label(
            default = "@com_github_scionproto_scion//rules_openapi/internal:header.sh",
            executable = True,
            cfg = "host",
            allow_files = True,
        ),
    },
    doc = "Adds a header to the src files.",
)
