load(":go_config.bzl", "GoLintInfo", "extract_dirs", "extract_files")

def _impi_impl(ctx):
    dirs = extract_dirs(ctx.attr.srcs, ctx.attr.lint_config)
    srcs = extract_files(ctx.attr.srcs, ctx.attr.lint_config)
    local = ctx.attr.local_prefix
    lc = ctx.attr.lint_config[GoLintInfo]
    if lc.impi_local_prefix != "":
        local = lc.impi_local_prefix

    test = [
        "#!/usr/bin/env bash",
        "echo \"{bin} -scheme {scheme} -local {local} {dirs}\"".format(
            bin = ctx.executable._impi_cli.short_path,
            scheme = ctx.attr.scheme,
            local = local,
            dirs = " ".join(dirs),
        ),
        "{bin} -scheme {scheme} -local {local} {dirs}".format(
            bin = ctx.executable._impi_cli.short_path,
            scheme = ctx.attr.scheme,
            local = local,
            dirs = " ".join(dirs),
        ),
    ]
    out = ctx.actions.declare_file(ctx.label.name + "_exec")
    ctx.actions.write(
        output = out,
        content = "\n".join(test),
    )
    runfiles = ctx.runfiles(
        files = srcs + [ctx.executable._impi_cli],
    )
    return [
        DefaultInfo(
            executable = out,
            runfiles = runfiles,
        ),
    ]

impi_test = rule(
    implementation = _impi_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "lint_config": attr.label(
            providers = [
                GoLintInfo,
            ],
        ),
        "local_prefix": attr.string(
            doc = "The prefix of the local repository",
            default = "github.com/scionproto/scion",
        ),
        "scheme": attr.string(
            doc = "The scheme to use",
            values = ["stdLocalThirdParty", "stdThirdPartyLocal"],
            default = "stdThirdPartyLocal",
        ),
        "_impi_cli": attr.label(
            cfg = "host",
            default = "@com_github_pavius_impi//cmd/impi",
            executable = True,
        ),
    },
    executable = True,
    test = True,
)
