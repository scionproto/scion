"""OpenAPI Macros
Macros for generating Go code from OpenAPI specs.
"""

load("//tools/lint:write_source_files.bzl", "write_source_files")
load("//rules_openapi:defs.bzl", _openapi_generate_go = "openapi_generate_go")
load("@npm//private/mgmtapi/tools:@redocly/cli/package_json.bzl", redocly_bin = "bin")
load("@aspect_bazel_lib//lib:transitions.bzl", "platform_transition_filegroup")

def openapi_docs(
        name,
        src,
        out,
        **kwargs):
    """
    Generates HTML documentation from an OpenAPI spec.

    Args:
        name: The name of the rule.
        src: The source spec file (yml).
        out: The output HTML file.
        **kwargs: Additional arguments to pass to openapi binary.
    """
    _target_platform_independent(
        redocly_bin.openapi,
        name = name,
        srcs = [src],
        outs = [out],
        args = ["build-docs", "--output", "../../../$@", "../../../$(location {})".format(src)],
        visibility = ["//visibility:private"],
        tags = ["manual"],
        **kwargs
    )

def openapi_bundle(
        name,
        entrypoint,
        visibility = None,
        srcs = [],
        **kwargs):
    """
    Generates a resolved spec file from a set of OpenAPI spec files.

    The file output will be under {{name}}.bzl.gen.yml.

    Args:
        name: The name of the rules.
        entrypoint: The entrypoint spec file.
        visibility: The visibility of the target.
        srcs: The list of spec files to bundle.
        **kwargs: Additional arguments to pass to openapi binary. (should be srcs)
    """
    redocly_bin.openapi(
        name = name + "-no-header",
        outs = [name + "-no-header.bzl.gen.yml"],
        srcs = srcs + [entrypoint],
        args = [
            "bundle",
            "--output",
            "../../../$@",
            "../../../$(location {})".format(entrypoint),
        ],
        **kwargs
    )
    _target_platform_independent(
        native.genrule,
        name = name,
        srcs = [name + "-no-header"],
        outs = [name + ".bzl.gen.yml"],
        cmd = "(echo '# GENERATED FILE DO NOT EDIT'; cat $<) > $@",
        visibility = visibility,
    )

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

    _target_platform_independent(
        _openapi_generate_go,
        name = name,
        **kwargs
    )

    write_source_files(
        name = "write_files",
        files = write_files,
    )

def _target_platform_independent(func, name, **kwargs):
    kwargs_vt = {}
    if "visibility" in kwargs:
        kwargs_vt["visibility"] = kwargs.pop("visibility")
    if "tags" in kwargs:
        kwargs_vt["tags"] = kwargs.pop("tags")

    func(
        name = name + "-platform-independent",
        visibility = ["//visibility:private"],
        tags = ["manual"],
        **kwargs
    )

    platform_transition_filegroup(
        name = name,
        srcs = [name + "-platform-independent"],
        target_platform = "@local_config_platform//:host",  # reset to default value, to allow reusing this for different target platforms
        **kwargs_vt
    )
