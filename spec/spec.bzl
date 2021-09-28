def oapi_codegen(name, package, generate, src, out, excludeSchemas = None):
    cmd = (
        "$(location @com_github_deepmap_oapi_codegen//cmd/oapi-codegen:oapi-codegen ) " +
        "--package " + package + " " +
        "--generate " + generate + " " +
        "-o $@ "
    )

    srcs = [src]
    if excludeSchemas:
        cmd += "--exclude-schemas $$(cat $(location " + excludeSchemas + ")) "
        srcs.append(excludeSchemas)

    # Source files must be the last input to the command.
    cmd += "$(location " + src + ")"

    native.genrule(
        name = name,
        srcs = srcs,
        outs = [out],
        cmd = cmd,
        tools = [
            "@com_github_deepmap_oapi_codegen//cmd/oapi-codegen:oapi-codegen",
        ],
    )

def generate_boilerplate(name, out, src = None, package = "api", server = True, client = True, spec = True, excludeSchemas = None):
    if not src:
        src = name + ".gen.yml"

    oapi_codegen(
        name = name + "-types",
        package = package,
        generate = "types",
        src = src,
        out = out + "/types.gen.go",
        excludeSchemas = excludeSchemas,
    )
    srcs = [":" + name + "-types"]

    if server:
        oapi_codegen(
            name = name + "-server",
            package = package,
            generate = "chi-server",
            src = src,
            out = out + "/server.gen.go",
        )
        srcs.append(":" + name + "-server")

    if client:
        oapi_codegen(
            name = name + "-client",
            package = package,
            generate = "client",
            src = src,
            out = out + "/client.gen.go",
        )
        srcs.append(":" + name + "-client")

    if spec:
        oapi_codegen(
            name = name + "-spec",
            package = package,
            generate = "spec",
            src = src,
            out = out + "/spec.gen.go",
        )
        srcs.append(":" + name + "-spec")

    native.filegroup(
        name = name,
        srcs = srcs,
    )
