load("@io_bazel_rules_go//go:def.bzl", "go_binary")

# Same as go_binary, but links the current version number into it.
def scion_go_binary(name, visibility, *args, **kwargs):
    x_defs = kwargs.get("x_defs", {})
    x_defs.update({
        "github.com/scionproto/scion/private/env.StartupVersion": "{STABLE_GIT_VERSION}",
    })

    go_binary(
        x_defs = x_defs,
        name = name,
        visibility = visibility,
        *args,
        **kwargs
    )

    native.genrule(
        name = name + "_compressed",
        srcs = [name, "//tools:gzip_exec_interp"],
        outs = [name + ".gunzip"],
        cmd = "(cat $(location //tools:gzip_exec_interp) && gzip < $(location " + name + ")) > $@",
        visibility = visibility,
    )
