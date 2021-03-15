def oapi_codegen(name, package, generate, src, out):
    native.genrule(
        name = name,
        srcs = [src],
        outs = [out],
        cmd = (
            "$(location @com_github_deepmap_oapi_codegen//cmd/oapi-codegen:oapi-codegen ) " +
            "--package " + package + " " +
            "--generate " + generate + " " +
            "-o $@ " +
            "$(location " + src + ")"
        ),
        tools = [
            "@com_github_deepmap_oapi_codegen//cmd/oapi-codegen:oapi-codegen",
        ],
    )

def generate_boilerplate(name, out, src = None, package = "api", server = True, client = True, spec = True):
    if not src:
        src = name + ".gen.yml"

    oapi_codegen(
        name = name + "-types",
        package = package,
        generate = "types",
        src = src,
        out = out + "/types.gen.go",
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
