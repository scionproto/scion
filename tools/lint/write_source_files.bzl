load("@aspect_bazel_lib//lib:write_source_files.bzl", _write_source_files = "write_source_files")

def write_source_files(name, **kwargs):
    """A wrapper around the aspect bazel lib write_source_files function.

    Args:
      name: The name of the rule
      **kwargs: The arguments as defined in the write_sources_files function.
    """

    tags = kwargs.get("tags", [])
    if "write_src" not in tags:
        tags = tags + ["write_src"]
    kwargs["tags"] = tags

    suggested_target = kwargs.get("suggested_update_target", None)
    if suggested_target == None:
        kwargs["suggested_update_target"] = "//:write_all_source_files"

    visibility = kwargs.get("visibility", None)
    if visibility == None:
        kwargs["visibility"] = ["//visibility:public"]

    _write_source_files(
        name = name,
        **kwargs
    )
