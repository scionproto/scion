load(":flake8_config.bzl", "Flake8Info")

def _flake8_impl(ctx):
    srcs = extract_files(ctx.attr.srcs)
    file_paths = short_paths(srcs)
    config = ctx.attr.lint_config[Flake8Info].config_file.files.to_list()[0]
    test = [
        "#!/usr/bin/env bash",
        "echo \"{bin} --config {config} {files}\"".format(
            bin = ctx.executable._flake8_cli.short_path,
            config = config.short_path,
            files = " ".join(file_paths),
        ),
        "{bin} --config {config} {files}".format(
            bin = ctx.executable._flake8_cli.short_path,
            config = config.short_path,
            files = " ".join(file_paths),
        ),
    ]
    out = ctx.actions.declare_file(ctx.label.name + "_exec")
    ctx.actions.write(
        output = out,
        content = "\n".join(test),
    )
    runfiles = ctx.runfiles(
        files = srcs + [config],
    )
    runfiles = runfiles.merge(ctx.attr._flake8_cli[DefaultInfo].default_runfiles)
    return [
        DefaultInfo(
            executable = out,
            runfiles = runfiles,
        ),
    ]

flake8_test = rule(
    implementation = _flake8_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "lint_config": attr.label(
            providers = [
                Flake8Info,
            ],
        ),
        "_flake8_cli": attr.label(
            cfg = "host",
            default = "//lint/private/python:flake8",
            providers = [
                DefaultInfo,
            ],
            executable = True,
        ),
    },
    executable = True,
    test = True,
)

def extract_files(srcs):
    filtered = []
    for s in srcs:
        files = s.files.to_list()
        for f in files:
            if f.dirname.startswith("external"):
                continue
            filtered.append(f)
    return filtered

def short_paths(files):
    sn = []
    for f in files:
        sn.append(f.short_path)
    return sn
