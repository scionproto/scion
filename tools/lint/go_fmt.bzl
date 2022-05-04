load("@io_bazel_rules_go//go:def.bzl", "go_context")
load("@bazel_skylib//lib:shell.bzl", "shell")

def _go_fmt_impl(ctx):
    go_ctx = go_context(ctx)
    gofmt = None
    for f in go_ctx.sdk.tools:
        if f.basename == "gofmt":
            gofmt = f
    if gofmt == None:
        fail("gofmt not found!")
    name = ctx.label.name
    out_file = ctx.actions.declare_file(name + ".fmt.go")
    cmd = "{bin} {src} > {out}".format(
        bin = gofmt.path,
        src = shell.quote(ctx.file.src.path),
        out = shell.quote(out_file.path),
    )
    ctx.actions.run_shell(
        outputs = [out_file],
        inputs = [ctx.file.src],
        tools = [gofmt],
        command = cmd,
        mnemonic = "GoFMT",
    )
    return [DefaultInfo(
        files = depset([out_file]),
    )]

go_fmt = rule(
    implementation = _go_fmt_impl,
    doc = "go_fmt can be used to gofmt a single file",
    attrs = {
        "src": attr.label(
            doc = "The file to gofmt.",
            allow_single_file = True,
        ),
    },
    toolchains = ["@io_bazel_rules_go//go:toolchain"],
)
