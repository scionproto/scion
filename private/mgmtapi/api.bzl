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

    write_files = {}
    for typ, gen in {"client": client, "server": server, "spec": spec, "types": types}.items():
        if not gen:
            continue
        src = typ + ".bzl.gen.go"
        kwargs["out_" + typ] = typ + ".bzl.gen.go"
        write_files[typ + ".gen.go"] = src

    _openapi_generate_go(
        name = name,
        **kwargs
    )

    write_source_files(
        name = "write_files",
        files = write_files,
    )
