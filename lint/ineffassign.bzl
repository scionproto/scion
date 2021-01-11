load(":go_config.bzl", "GoLintInfo", "extract_dirs", "extract_files")

def _ineffassign_impl(ctx):
    dirs = extract_dirs(ctx.attr.srcs, ctx.attr.lint_config)
    srcs = extract_files(ctx.attr.srcs, ctx.attr.lint_config)

    if len(dirs) == 0:
        # TODO(lukedirtwalker): optimally we already fix that earlier, i.e.
        # don't invoke the rule.
        out = ctx.actions.declare_file(ctx.label.name + "_exec")
        ctx.actions.write(
            output = out,
            content = "#!/usr/bin/env bash\necho skipped",
        )
        return [DefaultInfo(executable = out)]

    test = [
        "#!/usr/bin/env bash",
        "echo \"{bin} {dirs}\"".format(
            bin = ctx.executable._ineffassign_cli.short_path,
            dirs = " ".join(dirs),
        ),
        "{bin} {dirs}".format(
            bin = ctx.executable._ineffassign_cli.short_path,
            dirs = " ".join(dirs),
        ),
    ]
    out = ctx.actions.declare_file(ctx.label.name + "_exec")
    ctx.actions.write(
        output = out,
        content = "\n".join(test),
    )
    runfiles = ctx.runfiles(
        files = srcs + [ctx.executable._ineffassign_cli],
    )
    return [
        DefaultInfo(
            executable = out,
            runfiles = runfiles,
        ),
    ]

ineffassign_test = rule(
    implementation = _ineffassign_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "lint_config": attr.label(
            providers = [
                GoLintInfo,
            ],
        ),
        "_ineffassign_cli": attr.label(
            cfg = "host",
            default = "@com_github_oncilla_ineffassign//:ineffassign",
            executable = True,
        ),
    },
    executable = True,
    test = True,
)
