load("//rules_openapi/internal:generate.bzl", _openapi_generate_go = "openapi_generate_go")

def openapi_generate_go(
        name,
        **kwargs):
    _openapi_generate_go(
        name = name,
        **kwargs
    )
