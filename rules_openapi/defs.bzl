load("//rules_openapi/internal:generate.bzl", _openapi_generate_go = "openapi_generate_go")
load("//rules_openapi/internal:bundle.bzl", _openapi_bundle = "openapi_bundle")
load("//rules_openapi/internal:docs.bzl", _openapi_build_docs = "openapi_build_docs")
load("//rules_openapi/internal:header.bzl", _header = "header")
load("@cgrindel_bazel_starlib//updatesrc:defs.bzl", "updatesrc_update")

def openapi_bundle(
        name,
        srcs,
        entrypoint,
        visibility = None):
    _openapi_bundle(
        name = name,
        srcs = srcs,
        entrypoint = entrypoint,
        visibility = visibility,
    )

    _header_target = name + "-add-header"
    _header(
        name = _header_target,
        srcs = [":" + name],
        header = "# GENERATED FILE DO NOT EDIT",
    )

    updatesrc_update(
        name = name + "-update",
        deps = [":" + _header_target],
    )

def openapi_generate_go(
        name,
        **kwargs):
    _openapi_generate_go(
        name = name,
        **kwargs
    )

    generate = {
        "types": kwargs.get("types", True),
        "server": kwargs.get("server", True),
        "client": kwargs.get("client", True),
        "spec": kwargs.get("spec", True),
    }

    srcs = []
    for k, v in generate.items():
        if not v:
            continue
        srcs.append(k + ".gen.go")
    updatesrc_update(
        name = name + "-update",
        srcs = srcs,
        outs = [":" + name],
    )

def openapi_build_docs(
        name,
        src,
        out,
        **kwargs):
    _openapi_build_docs(
        name = name,
        src = src,
        out = out,
        **kwargs
    )
