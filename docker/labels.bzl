load("@aspect_bazel_lib//lib:expand_template.bzl", "expand_template")
load("@bazel_skylib//rules:write_file.bzl", "write_file")

# Labels for scion docker images.
#   org.scion=_
# is just a tag identifying this image as generated for scion.
#
# With --stamp, we add
#   org.scion.version=<git tag>
def scion_labels():
    expand_template(
        name = "labels",
        out = "labels.txt",
        stamp_substitutions = {
            "MAYBE_VERSION": "org.scion.version=v{{STABLE_GIT_VERSION}}\n",
        },
        substitutions = {"MAYBE_VERSION": ""},
        template = "labels_tmpl",
        visibility = ["//visibility:public"],
    )

    write_file(
        name = "labels_tmpl",
        out = "labels.txt.tmpl",
        content = [
            "org.scion=_",
            "MAYBE_VERSION",
        ],
        visibility = ["//visibility:private"],
        tags = ["manual"],
    )
