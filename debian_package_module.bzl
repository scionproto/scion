load("@rules_debian_packages//debian_packages:defs.bzl", "debian_packages_repository")

def _debian_package_repo_impl(mctx):
    debian_packages_repository(
        name = "tester_debian10_packages",
        default_arch = "amd64",
        default_distro = "debian10",
        lock_file = "//docker:tester_packages.lock",
    )

debian_package_repo = module_extension(
    implementation = _debian_package_repo_impl,
)
