load("@rules_antlr//antlr:repositories.bzl", "rules_antlr_dependencies")

download = tag_class(attrs = {"version": attr.string()})

def _antlr(module_ctx):
    rules_antlr_dependencies(
        max([
            ([int(part) for part in download.version.split(".")], download.version)
            for mod in module_ctx.modules
            for download in mod.tags.download
        ])[1],
    )

antlr = module_extension(
    implementation = _antlr,
    tag_classes = {"download": download},
)
