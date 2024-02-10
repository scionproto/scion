load("@rules_pkg//pkg:pkg.bzl", "pkg_deb", "pkg_tar")
load("//:versioning.bzl", "STRIPPED_GIT_VERSION")

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

# As stupefying as it may seem, neither genrule nor aspect.file_copy() support
# configurable output and input. Yet, nothing fundamentally prevents it. See:
def _impl_copy_file(ctx):
    in_file = ctx.file.src
    out_file = ctx.actions.declare_file(ctx.attr.out)
    ctx.actions.run_shell(
        inputs = [in_file],
        outputs = [out_file],
        progress_message = "Copying %{input} to %{output}",
        arguments = [
            in_file.path,
            out_file.path,
        ],
        command = "cp -f $1 $2",
    )
    return DefaultInfo(files = depset([out_file]))

copy_file = rule(
    implementation = _impl_copy_file,
    attrs = {
        "src": attr.label(
            mandatory = True,
            allow_single_file = True,
        ),
        "out": attr.string(
            mandatory = True,
        ),
    },
)

def scion_pkg_ipk(name, package, **kwargs):
    """
    The package labeled @openwrt_<target_arch>_SDK//:<name> is built and copied to
    <package>__<target_arch>.ipk.

    @openwrt_<target_arch>_SDK is an external dependency. Their build file is BUILD.external.bazel.
    For the build of the package to be possible, the openwrt_<target_arch>_SDK tree must be
    imported by way of an http_archive directive in //WORKSPACE.

    target_arch is the specific target cpu as understood by the openwrt toolchain. It is mapped
    from the cpu as is understood by bazel plaform (as in --platforms=[...]) for which we build.
    """
    tag, count, commit, dirty = STRIPPED_GIT_VERSION.split("-")
    version = (tag + "-" + count + "-" + dirty) if dirty else (tag + "-" + count)
    copy_file(
        name = name,
        # The final target and file names cannot be evaluated before action time. So we have to pass
        # the entire unresolved select expression. There may be ways around this, but just as ugly.
        src = select({
            "@platforms//cpu:x86_64": "@openwrt_x86_64_SDK//:" + name,
        }),
        out = select ({
            "@platforms//cpu:x86_64": package + "_" + version + "_x86_64.ipk",
        }),
        **kwargs,
    )

def _basename(s):
    return s.split("/")[-1]

