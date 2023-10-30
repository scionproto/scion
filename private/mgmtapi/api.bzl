"""OpenAPI Macros
Macros for generating Go code from OpenAPI specs.
"""

load("//tools/lint:write_source_files.bzl", "write_source_files")
load("//rules_openapi:defs.bzl", _openapi_generate_go = "openapi_generate_go")

def openapi_generate_go(
        name,
        client = True,
        server = True,
        spec = True,
        types = True,
        **kwargs):
    """
    Generates Go code from an OpenAPI spec.

    This macro creates two additional rules:
    - {{name}}_files: A filegroup with the generated files.
    - write_files: A write_source_files rule that writes the generated files to
      the source directory.

    Args:
        name: The name of the rule.
        client: Whether to generate a client.
        server: Whether to generate a server.
        spec: Whether to generate a spec.
        types: Whether to generate types.
        **kwargs: Ad.
    """

    _openapi_generate_go(
        name = name + "_gen",
        out_client = "client.bzl.gen.go" if client else None,
        out_server = "server.bzl.gen.go" if server else None,
        out_spec = "spec.bzl.gen.go" if spec else None,
        out_types = "types.bzl.gen.go" if types else None,
        **kwargs
    )

    out_files = []
    write_files = {}
    for typ, gen in {"client": client, "server": server, "spec": spec, "types": types}.items():
        if not gen:
            continue
        src = typ + ".bzl.gen.go"
        out_files.append(src)
        write_files[typ + ".gen.go"] = src

    native.filegroup(
        name = name,
        srcs = out_files,
    )

    write_source_files(
        name = "write_files",
        files = write_files,
    )
