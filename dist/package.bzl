load("@rules_pkg//pkg:pkg.bzl", "pkg_deb", "pkg_tar")

SCION_PKG_HOMEPAGE = "https://github.com/scionproto/scion"
SCION_PKG_MAINTAINER = "SCION Contributors"
SCION_PKG_LICENSE = "Apache 2.0"
SCION_PKG_PRIORITY = "optional"
SCION_PKG_SECTION = "net"

def scion_pkg_deb(name, executables = {}, systemds = [], configs = [], **kwargs):
    """
    The package content, the _data_ arg for the pkg_deb rule, is assembled from:

    - executables: Map Label (the executable) -> string, the basename of the executable in the package
      Executables are installed to /usr/bin/
    - systemds: List[string], the systemd unit files to be installed in /lib/systemd/system/
    - configs:  List[string], the configuration files to be installed in /etc/scion/

    The values for the following pkg_deb args are set to a default value:
    - homepage
    - maintainer
    - priority
    - section
    - license
    - conffiles, set based on data.configs
    - architecture, set based on the platform.

    The caller needs to set:
    - package
    - description
    - version/version_file
    and any of the optional control directives.
    """

    data = "%s_data" % name
    _scion_pkg_deb_data(
        name = data,
        executables = executables,
        systemds = systemds,
        configs = configs,
        visibility = ["//visibility:private"],
        tags = ["manual"],
    )
    conffiles = ["/etc/scion/" + _basename(file) for file in configs]

    kwargs.setdefault("homepage", SCION_PKG_HOMEPAGE)
    kwargs.setdefault("maintainer", SCION_PKG_MAINTAINER)
    kwargs.setdefault("priority", SCION_PKG_PRIORITY)
    kwargs.setdefault("section", SCION_PKG_SECTION)
    kwargs.setdefault("license", SCION_PKG_LICENSE)
    kwargs.setdefault("conffiles", conffiles)
    if "architecture" not in kwargs:
        kwargs["architecture"] = select({
            "@platforms//cpu:x86_64": "amd64",
            "@platforms//cpu:x86_32": "i386",
            "@platforms//cpu:aarch64": "arm64",
            "@platforms//cpu:arm": "armel",
            "@platforms//cpu:s390x": "s390x",
            # Note: some rules_go toolchains don't (currently) seem to map (cleanly) to @platforms//cpu.
            # "@platforms//cpu:ppc": "ppc64",
            # "@platforms//cpu:ppc64le": "ppc64le",
        })
    pkg_deb(
        name = name,
        data = data,
        target_compatible_with = ["@platforms//os:linux"],
        **kwargs
    )

def _scion_pkg_deb_data(name, executables, systemds, configs, **kwargs):
    executable_files = {label: "/usr/bin/" + basename for label, basename in executables.items()}
    systemd_files = {file: "/lib/systemd/system/" + _basename(file) for file in systemds}
    config_files = {file: "/etc/scion/" + _basename(file) for file in configs}

    files = {}
    files.update(executable_files)
    files.update(systemd_files)
    files.update(config_files)

    pkg_tar(
        name = name,
        extension = "tar.gz",
        files = files,
        modes = {
            exec_filepath: "755"
            for exec_filepath in executable_files.values()
        },
        mode = "644",  # for everything else
        **kwargs
    )

def _basename(s):
    return s.split("/")[-1]
