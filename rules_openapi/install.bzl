load(
    "@build_bazel_rules_nodejs//:index.bzl",
    "node_repositories",
    "yarn_install",
)

PACKAGE_JSON = "@com_github_scionproto_scion//rules_openapi/tools:package.json"

def rules_openapi_install_yarn_dependencies():
    node_repositories(
        package_json = [PACKAGE_JSON],
    )
    yarn_install(
        name = "rules_openapi_npm",
        # Opt out of directory artifacts, we rely on ts_library which needs
        # to see labels for all third-party files.
        exports_directories_only = False,
        package_json = PACKAGE_JSON,
        yarn_lock = "@com_github_scionproto_scion//rules_openapi/tools:yarn.lock",
    )
