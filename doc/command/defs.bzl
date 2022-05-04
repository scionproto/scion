def _recursive_copy_output_impl(ctx):
    generated_dir = ctx.file.input_dir
    output_dir = ctx.file.output_dir

    # Make sure that the directories are available to the update script.
    runfiles = ctx.runfiles(files = [generated_dir, output_dir])

    # Declare the update script + specify it's content
    update_sh = ctx.actions.declare_file(
        ctx.label.name + "_update.sh",
    )
    extra_script = ""
    if ctx.attr.file_transformation:
        extra_script = "\nfor FILE in {output_dir}/*; do {file_transformation} ; done".format(
            output_dir = output_dir.short_path,
            file_transformation = ctx.attr.file_transformation,
        )
    ctx.actions.write(
        output = update_sh,
        content = """
#!/usr/bin/env bash
runfiles_dir=$(pwd)
# When run from a test, build workspace directory is not set. The
# source copy just happens in the sandbox.
if [[ ! -z "${BUILD_WORKSPACE_DIRECTORY}" ]]; then
  cd "${BUILD_WORKSPACE_DIRECTORY}"
fi
""" + "\nrm -rf {output_dir}/*\ncp -rf -t {output_dir} $(readlink \"${{runfiles_dir}}/{generated_dir}\")/*\nchmod -R 0755 {output_dir}".format(
            generated_dir = generated_dir.short_path,
            output_dir = output_dir.short_path,
        ) + extra_script,
        is_executable = True,
    )
    return [DefaultInfo(executable = update_sh, runfiles = runfiles)]

recursive_copy_output = rule(
    implementation = _recursive_copy_output_impl,
    attrs = {
        "input_dir": attr.label(
            mandatory = True,
            allow_single_file = True,
        ),
        "output_dir": attr.label(
            mandatory = True,
            allow_single_file = True,
        ),
        "file_transformation": attr.string(
            doc = "Input the function of a for loop which iterates over every file generated",
        ),
    },
    executable = True,
)
