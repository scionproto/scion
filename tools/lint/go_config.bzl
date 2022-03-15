GoLintInfo = provider(
    fields = {
        "exclude_filter": "parts of the file name that lead to exclusion from lint checks",
        "impi_local_prefix": "The local prefix attribute for impi",
    },
)

def _go_lint_config_impl(ctx):
    return [
        GoLintInfo(
            exclude_filter = ctx.attr.exclude_filter,
            impi_local_prefix = ctx.attr.impi_local_prefix,
        ),
    ]

go_lint_config = rule(
    _go_lint_config_impl,
    attrs = {
        "exclude_filter": attr.string_list(
            doc = "The parts of the file name that lead to exclusion from lint checks",
        ),
        "impi_local_prefix": attr.string(
            doc = "The local prefix attribute for impi",
        ),
    },
    provides = [
        GoLintInfo,
    ],
)

def extract_dirs(srcs, lint_config):
    excludes = lint_config[GoLintInfo].exclude_filter
    if excludes == None:
        excludes = []
    dirs = {}
    for s in srcs:
        files = s.files.to_list()
        for f in files:
            if _is_exlcuded(f, excludes):
                continue
            dirs[f.dirname] = ""
    return dirs.keys()

def extract_files(srcs, lint_config):
    excludes = lint_config[GoLintInfo].exclude_filter
    if excludes == None:
        excludes = []
    filtered = []
    for s in srcs:
        files = s.files.to_list()
        for f in files:
            if _is_exlcuded(f, excludes):
                continue
            filtered.append(f)
    return filtered

def _is_exlcuded(f, excludes):
    for e in excludes:
        if e in f.short_path:
            return True
    return False
