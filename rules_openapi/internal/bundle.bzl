load("@bazel_skylib//lib:shell.bzl", "shell")

def _openapi_bundle_impl(ctx):
    prefix = ctx.label.name
    out_file = ctx.actions.declare_file(prefix + ".gen.yml")
    cmd = "{bin} bundle --output {out} {entrypoint}".format(
        bin = ctx.executable._openapi_cli.path,
        out = shell.quote(out_file.path),
        entrypoint = shell.quote(ctx.file.entrypoint.path),
    )

    ctx.actions.run_shell(
        outputs = [out_file],
        inputs = [ctx.file.entrypoint] + ctx.files.srcs,
        tools = [ctx.executable._openapi_cli],
        command = cmd,
        mnemonic = "OpenAPIBundle",
        use_default_shell_env = True,
    )
    return [DefaultInfo(
        files = depset([out_file]),
    )]

openapi_bundle = rule(
    implementation = _openapi_bundle_impl,
    doc = "This rule can be used to bundle open API specification files.",
    attrs = {
        "srcs": attr.label_list(
            doc = "All files that are referenced in the entrypoint file",
            allow_files = [".yml"],
        ),
        "entrypoint": attr.label(
            doc = "The main source to generate files from",
            allow_single_file = [".yml"],
            mandatory = True,
        ),
        "_openapi_cli": attr.label(
            default = "@rules_openapi_npm//@redocly/cli/bin:openapi",
            executable = True,
            cfg = "target",
        ),
    },
)
