def _git_version_impl(ctx):
    ctx.actions.run_shell(
        outputs = [ctx.outputs.outfile],
        inputs = [ctx.info_file],
        command = r"sed -n 's/STABLE_GIT_VERSION\s*//p' " + ctx.info_file.path + " > " + ctx.outputs.outfile.path,
    )

git_version = rule(
    doc = """
    Extracts the STABLE_GIT_VERSION from the workspace_status_command output.
    See also .bazelrc and tools/bazel-build-env.

    The output of this rule is a file containing the version only. The leading "v" from the git tag
    is removed by tools/git-version so workspace_status_command never even sees it.
    """,
    implementation = _git_version_impl,
    outputs = {
        "outfile": "git-version",
    },
)
