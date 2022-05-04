Flake8Info = provider(
    fields = {
        "config_file": "The configuration file for flake8.",
    },
)

def _flake8_lint_config_impl(ctx):
    return [
        Flake8Info(
            config_file = ctx.attr.config_file,
        ),
    ]

flake8_lint_config = rule(
    _flake8_lint_config_impl,
    attrs = {
        "config_file": attr.label(
            doc = "The configuration file to use for flake8.",
            allow_files = True,
        ),
    },
    provides = [
        Flake8Info,
    ],
)
