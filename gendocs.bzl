def _docs_impl(ctx):
  dir = ctx.actions.declare_directory("docs")

  ctx.actions.run(
      inputs = [],
      outputs = [ dir ],
      arguments = [ "gendocs", dir.path ],
      progress_message = "Generating doc files into '%s'" % dir.path,
      executable = ctx.executable.tool,
  )

  return [ DefaultInfo(files = depset([ dir])) ]

gendocs = rule(
    implementation=_docs_impl,
    attrs = {
        "tool": attr.label(
            executable = True,
            cfg = "host",
            allow_files = True,
            mandatory = True,
        )
    }
)
