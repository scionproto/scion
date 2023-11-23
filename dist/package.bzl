load("@rules_pkg//pkg:pkg.bzl", "pkg_deb", "pkg_tar")
load("@aspect_bazel_lib//lib:transitions.bzl", "platform_transition_filegroup")

SCION_PKG_GIT_VERSION = "0.9.1"
SCION_PKG_REVISION = "1"
SCION_PKG_VERSION = "%s-%s" % (SCION_PKG_GIT_VERSION, SCION_PKG_REVISION)

SCION_PKG_HOMEPAGE = "https://github.com/scionproto/scion"
SCION_PKG_MAINTAINER = "SCION Contributors"
SCION_PKG_LICENSE = "Apache 2.0"
SCION_PKG_PRIORITY = "optional"
SCION_PKG_SECTION = "net"

SCION_PKG_PLATFORMS = {
    "@io_bazel_rules_go//go/toolchain:linux_amd64": "amd64",
    "@io_bazel_rules_go//go/toolchain:linux_arm64": "arm64",
    "@io_bazel_rules_go//go/toolchain:linux_386": "i386",
    "@io_bazel_rules_go//go/toolchain:linux_arm": "armel", # default GOARM=5, armhf would be GOARM=6; not sure how to set
}

def scion_multiarch_pkg_deb(name, executables = {}, systemds = [], configs = [], **kwargs):
    """
    Create a pkg_deb rule for a fixed range of supported platforms.

    The package content, the _data_ arg for the pkg_deb rule, is assembled from:

    - executables: Map Label (the executable) -> string, the basename of the executable in the package
      Executables are installed to /usr/bin/
    - systemds: List[string], the systemd unit files to be installed in /lib/systemd/system/
    - configs:  List[string], the configuration files to be installed in /etc/scion/

    The values for the pkg_deb args
    - homepage
    - maintainer
    - priority
    - section
    - license
    - version
    - conffiles
    default to SCION-specific values, but can be overridden.
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
    conffiles = [ "/etc/scion/" + _basename(file) for file in configs ] # FIXME deduplicate
    kwargs.setdefault('conffiles', conffiles)

    pkgs = []
    for target_platform, architecture in SCION_PKG_PLATFORMS.items():
        pkg_arch = "%s_%s" % (name, architecture)
        data_arch = "%s_data_%s" % (name, architecture)
        platform_transition_filegroup(
            name = data_arch,
            srcs = [data],
            target_platform = target_platform,
            visibility = ["//visibility:private"],
            tags = ["manual"],
        )
        _scion_pkg_deb(
            name = pkg_arch,
            data = data_arch,
            architecture = architecture,
            **kwargs,
        )
        pkgs.append(pkg_arch)

    native.filegroup(
        name = name,
        srcs = pkgs,
    )

def _scion_pkg_deb_data(name, executables, systemds, configs, **kwargs):
    executable_files = { label : "/usr/bin/" + basename for label, basename in executables.items() }
    systemd_files = { file : "/lib/systemd/system/" + _basename(file) for file in systemds }
    config_files = { file : "/etc/scion/" + _basename(file) for file in configs }

    files = {}
    files.update(executable_files)
    files.update(systemd_files)
    files.update(config_files)

    pkg_tar(
        name = name,
        extension = "tar.gz",
        files = files,
        # executables should be executable
        modes = {
            exec_filepath: "755" for exec_filepath in executable_files.values()
        },
        mode = "644", # for everything else
        **kwargs,
    )

def _scion_pkg_deb(name, **kwargs):
    kwargs.setdefault('homepage', SCION_PKG_HOMEPAGE)
    kwargs.setdefault('maintainer', SCION_PKG_MAINTAINER)
    kwargs.setdefault('priority', SCION_PKG_PRIORITY)
    kwargs.setdefault('section', SCION_PKG_SECTION)
    kwargs.setdefault('license', SCION_PKG_LICENSE)
    kwargs.setdefault('version', SCION_PKG_VERSION)
    pkg_deb(
        name = name,
        **kwargs
    )

def _basename(s):
  return s.split('/')[-1]
