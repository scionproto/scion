load("//rules_openapi/internal:generate.bzl", _openapi_generate_go = "openapi_generate_go")
load("//rules_openapi/internal:bundle.bzl", _openapi_bundle = "openapi_bundle")
load("//rules_openapi/internal:docs.bzl", _openapi_build_docs = "openapi_build_docs")

def openapi_bundle(
        name,
        srcs,
        entrypoint,
        visibility = None):
    _openapi_bundle(
        name = name + "-no-header",
        out = name + "-no-header.bzl.gen.yml",
        srcs = srcs,
        entrypoint = entrypoint,
    )
    native.genrule(
        name = name,
        srcs = [name + "-no-header"],
        outs = [name + ".bzl.gen.yml"],
        cmd = "(echo '# GENERATED FILE DO NOT EDIT'; cat $<) > $@",
        visibility = visibility,
    )

def openapi_generate_go(
        name,
        **kwargs):
    _openapi_generate_go(
        name = name,
        **kwargs
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
