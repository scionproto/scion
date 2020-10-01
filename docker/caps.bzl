# Copyright 2017 The Bazel Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Copyright 2020 Anapaya Systems
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This file was initially copied from ocker/docker/util/run.bzl and then adapted,
# see https://github.com/bazelbuild/rules_docker/blob/master/docker/util/run.bzl

"""
Rules to set capabilities on a container. The container must have the `setcap`
binary in it.
"""

load("@io_bazel_rules_docker//container:container.bzl", "container_image")

def _setcap_impl(ctx):
    """Implementation for the setcap rule.
    This rule sets capabilities on a binary in an image and stores the image.
    Args:
        ctx: The bazel rule context.
    """

    name = ctx.attr.name
    image = ctx.file.image
    script = ctx.outputs.build
    output_image_tar = ctx.outputs.out

    toolchain_info = ctx.toolchains["@io_bazel_rules_docker//toolchains/docker:toolchain_type"].info

    # Generate a shell script to execute the reset cmd
    image_utils = ctx.actions.declare_file("image_util.sh")
    ctx.actions.expand_template(
        template = ctx.file._image_utils_tpl,
        output = image_utils,
        substitutions = {
            "%{docker_flags}": " ".join(toolchain_info.docker_flags),
            "%{docker_tool_path}": toolchain_info.tool_path,
        },
        is_executable = True,
    )

    # Generate a shell script to execute the setcap statement
    ctx.actions.expand_template(
        template = ctx.file._run_tpl,
        output = script,
        substitutions = {
            "%{caps}": ctx.attr.caps,
            "%{binary}": ctx.attr.binary,
            "%{docker_flags}": " ".join(toolchain_info.docker_flags),
            "%{docker_tool_path}": toolchain_info.tool_path,
            "%{image_id_extractor_path}": ctx.executable._extract_image_id.path,
            "%{image_tar}": image.path,
            "%{output_image}": "bazel/%s:%s" % (
                ctx.label.package or "default",
                name,
            ),
            "%{output_tar}": output_image_tar.path,
            "%{to_json_tool}": ctx.executable._to_json_tool.path,
            "%{util_script}": image_utils.path,
        },
        is_executable = True,
    )

    runfiles = [image, image_utils]

    ctx.actions.run(
        outputs = [output_image_tar],
        inputs = runfiles,
        executable = script,
        tools = [ctx.executable._extract_image_id, ctx.executable._to_json_tool],
        use_default_shell_env = True,
    )

    return struct()

_setcap_attrs = {
    "image": attr.label(
        doc = "The image without caps set.",
        mandatory = True,
        allow_single_file = True,
        cfg = "target",
    ),
    "caps": attr.string(
        doc = "The capabilities to add, (example: cap_net_admin+ei)",
        mandatory = True,
    ),
    "binary": attr.string(
        doc = "The binary to set the capabilities on, (example: /app/sig)",
        mandatory = True,
    ),
    "_extract_image_id": attr.label(
        default = Label("@io_bazel_rules_docker//contrib:extract_image_id"),
        cfg = "host",
        executable = True,
        allow_files = True,
    ),
    "_image_utils_tpl": attr.label(
        default = "@io_bazel_rules_docker//docker/util:image_util.sh.tpl",
        allow_single_file = True,
    ),
    "_run_tpl": attr.label(
        default = Label("//docker:setcap.sh.tpl"),
        allow_single_file = True,
    ),
    "_to_json_tool": attr.label(
        default = Label("@io_bazel_rules_docker//docker/util:to_json"),
        cfg = "host",
        executable = True,
        allow_files = True,
    ),
}
_setcap_outputs = {
    "out": "%{name}.tar",
    "build": "%{name}.build",
}

setcap = rule(
    attrs = _setcap_attrs,
    doc = ("This rules setcap a binary in an image"),
    executable = False,
    outputs = _setcap_outputs,
    implementation = _setcap_impl,
    toolchains = ["@io_bazel_rules_docker//toolchains/docker:toolchain_type"],
)

# same as container_image, except that it allows to set capabilities on one binary
def container_image_setcap(name, entrypoint, cmd = None, caps_binary = None, caps = None, **kwargs):
    if not caps:
        # Fast path. If no caps are to be set, skip the setcap dance.
        container_image(
            name = name,
            cmd = cmd,
            entrypoint = entrypoint,
            visibility = ["//visibility:public"],
            **kwargs
        )
    else:
        container_image(
            name = name + "_nocap",
            cmd = cmd,
            entrypoint = entrypoint,
            **kwargs
        )
        setcap(
            name = name + "_withcap",
            image = name + "_nocap.tar",
            caps = caps,
            binary = caps_binary,
        )
        container_image(
            name = name,
            base = name + "_withcap.tar",
            cmd = cmd,
            entrypoint = entrypoint,
            visibility = ["//visibility:public"],
        )
