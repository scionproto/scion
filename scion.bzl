load("@io_bazel_rules_go//go:def.bzl", "go_binary")

# Same as go_binary, but links the current version number into it.
def scion_go_binary(*args, **kwargs):
    x_defs = kwargs.get("x_defs", {})
    x_defs.update({
        "github.com/scionproto/scion/go/lib/env.StartupVersion": "{STABLE_GIT_VERSION}",
    })
    go_binary(x_defs = x_defs, *args, **kwargs)
