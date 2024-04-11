def _sphinx_lint_test_impl(ctx):
    args = list(ctx.attr.args)
    for s in ctx.files.srcs:
        args.append(s.short_path)

    out = ctx.actions.declare_file(ctx.label.name + "_exec")
    ctx.actions.write(
        output = out,
        content = """
        #!/usr/bin/env bash
        exec {bin} {args}
        """.format(
            bin = ctx.executable._sphinx_lint_cli.short_path,
            args = " ".join(args),
        ),
    )

    deps = ctx.attr._sphinx_lint_cli.default_runfiles.files.to_list()

    runfiles = ctx.runfiles(
        files = ctx.files.srcs + deps,
    )
    return [
        DefaultInfo(
            executable = out,
            runfiles = runfiles,
        ),
    ]

sphinx_lint_test = rule(
    implementation = _sphinx_lint_test_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "_sphinx_lint_cli": attr.label(
            cfg = "host",
            default = "//doc:sphinx-lint",
            executable = True,
        ),
    },
    test = True,
)
