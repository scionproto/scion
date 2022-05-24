load("@bazel_skylib//lib:shell.bzl", "shell")

def _openapi_generate_go(ctx):
    generate = {
        "types": ctx.attr.types,
        "server": ctx.attr.server,
        "client": ctx.attr.client,
        "spec": ctx.attr.spec,
    }
    out_files = []
    for k, v in generate.items():
        if not v:
            continue
        out_file = ctx.actions.declare_file(k + ".gen.go")
        generate_kind = k
        if generate_kind == "server":
            generate_kind = "chi-server"
        cmd = "{bin} -package {package} -generate {generate} -o {out}".format(
            bin = ctx.executable._oapi_codegen.path,
            package = shell.quote(ctx.attr.package),
            generate = generate_kind,
            out = shell.quote(out_file.path),
        )
        extra_inputs = []
        if generate_kind == "types" and ctx.file.types_excludes != None:
            cmd = cmd + " -exclude-schemas $(cat {excludes_file})".format(
                excludes_file = shell.quote(ctx.file.types_excludes.path),
            )
            extra_inputs.append(ctx.file.types_excludes)

        # if a templates folder is provided add it to the command
        if bool(ctx.files.templates):
            templates_folder = ctx.files.templates[0].dirname
            if templates_folder.split("/")[::-1][0] != "templates":
                fail("The parent directory of the first filegroup file should be 'templates'")
            cmd += " -templates {folder}".format(
                folder = templates_folder,
            )

        # Source files must be the last input to the command.
        cmd += " {src}".format(
            src = shell.quote(ctx.file.src.path),
        )

        ctx.actions.run_shell(
            outputs = [out_file],
            inputs = [ctx.file.src] + extra_inputs + ctx.files.templates,
            tools = [ctx.executable._oapi_codegen],
            command = cmd,
            mnemonic = "OpenAPIGoGen",
            use_default_shell_env = True,
        )

        out_files.append(out_file)

    return [
        DefaultInfo(files = depset(out_files)),
    ]

openapi_generate_go = rule(
    implementation = _openapi_generate_go,
    doc = "This rule generate Go files from a given open API specification.",
    attrs = {
        "src": attr.label(
            doc = "The input specification file.",
            allow_single_file = [".yml"],
        ),
        "package": attr.string(
            doc = "The Go package the generated code should live in.",
            default = "api",
        ),
        "types": attr.bool(
            doc = "Whether the types file should be generated",
            default = True,
        ),
        "types_excludes": attr.label(
            doc = "The file containing the schema list to exclude during the types generation.",
            allow_single_file = True,
        ),
        "server": attr.bool(
            doc = "Whether the server code should be generated",
            default = True,
        ),
        "client": attr.bool(
            doc = "Whehter the client code should be generated",
            default = True,
        ),
        "spec": attr.bool(
            doc = "Whether the spec code should be generated",
            default = True,
        ),
        "templates": attr.label_list(
            doc = """Folder containing Go templates to be used during code generation.
                Note that the template file names need to match the ones used by the
                openapi codegen.
                (see https://github.com/deepmap/oapi-codegen#making-changes-to-code-generation)""",
            allow_files = [".tmpl"],
        ),
        "_oapi_codegen": attr.label(
            doc = "The code generator binary.",
            default = "@com_github_deepmap_oapi_codegen//cmd/oapi-codegen:oapi-codegen",
            executable = True,
            cfg = "target",
        ),
    },
)
