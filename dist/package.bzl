load("@rules_pkg//pkg:pkg.bzl", "pkg_deb", "pkg_tar")
load("@rules_pkg//pkg:rpm.bzl", "pkg_rpm")
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@rules_pkg//pkg:providers.bzl", "PackageVariablesInfo")
load("@rules_pkg//pkg:mappings.bzl", "pkg_attributes", "pkg_files")

SCION_PKG_HOMEPAGE = "https://github.com/scionproto/scion"
SCION_PKG_MAINTAINER = "SCION Contributors"
SCION_PKG_LICENSE = "Apache 2.0"
SCION_PKG_PRIORITY = "optional"
SCION_PKG_SECTION = "net"

def _name_elems_impl(ctx):
    values = {}
    values["file_name_version"] = ctx.attr.file_name_version[BuildSettingInfo].value
    values["package"] = ctx.attr.package
    values["architecture"] = ctx.attr.architecture
    return PackageVariablesInfo(values = values)

name_elems = rule(
    implementation = _name_elems_impl,
    attrs = {
        "file_name_version": attr.label(
            doc = "Placeholder for our file name version string cmd line arg.",
        ),
        "package": attr.string(
            doc = "Placeholder for our file name package name string.",
        ),
        "architecture": attr.string(
            doc = "Placeholder for our file name architecture string.",
        ),
    },
)

def scion_pkg_rpm(name, package, executables = {}, systemds = [], configs = [], **kwargs):
    """
    The package content, the _data_ arg for the pkg_rpm rule, is assembled from:

    - executables: Map Label (the executable) -> string, the basename of the executable in the package
      Executables are installed to /usr/bin/
    - systemds: List[string], the systemd unit files to be installed in /lib/systemd/system/
    - configs:  List[string], the configuration files to be installed in /etc/scion/

    The values for the following pkg_rpm args are set to a default value:
    - url
    - license
    - architecture, set based on the platform.

    The caller needs to set:
    - package: the name of the package (e.g. scion-router)
    - description: one-liner
    - version/version_file: One can use the label ":git_version"
    and any of the optional control directives.

    The version string gets edited to meet rpm requirements: dashes are replaced with ^.
    """

    kwargs.setdefault("url", SCION_PKG_HOMEPAGE)
    kwargs.setdefault("license", SCION_PKG_LICENSE)

    if "architecture" not in kwargs:
        kwargs["architecture"] = select({
            "@platforms//cpu:x86_64": "x86_64",
            "@platforms//cpu:x86_32": "i386",
            "@platforms//cpu:aarch64": "arm64",
            "@platforms//cpu:armv7": "armel",
            "@platforms//cpu:s390x": "s390x",
            # Note: some rules_go toolchains don't (currently) seem to map (cleanly) to @platforms//cpu.
            # "@platforms//cpu:ppc": "ppc64",
            # "@platforms//cpu:ppc64le": "ppc64le",
        })

    name_elems(
        name = "package_file_naming_" + name,
        file_name_version = "@@//:file_name_version",
        architecture = kwargs["architecture"],
        package = package,
    )

    # Note that our "executables" parameter is a dictionary label->file_name; exactly what pkg_files
    # wants for its "renames" param.
    pkg_files(name = "%s_configs" % name, prefix = "/etc/scion/", srcs = configs)
    pkg_files(name = "%s_systemds" % name, prefix = "/lib/systemd/system/", srcs = systemds)
    pkg_files(
        name = "%s_execs" % name,
        prefix = "/usr/bin/",
        srcs = executables.keys(),
        attributes = pkg_attributes(mode = "0755"),
        renames = executables,
    )

    if kwargs.get("version_file"):
        native.genrule(
            name = "%s_version" % name,
            srcs = [kwargs["version_file"]],
            outs = ["%s_version_file" % name],
            cmd = "sed 's/-/^/g' < $< > $@",
        )
        kwargs.pop("version_file")
    elif kwargs.get("version"):
        native.genrule(
            name = "%s_version" % name,
            srcs = [],
            outs = ["%s_version_file" % name],
            cmd = "echo \"%s\" | sed 's/-/^/g' > $@" % kwargs["version"],
        )
        kwargs.pop("version")

    # Use the same attributes as scion_pkg_deb, in view of may-be simplifying BUILD.bazel later.
    deps = kwargs.get("depends")
    if deps:
        kwargs.pop("depends")
    else:
        deps = []

    post = kwargs.get("postinst")
    if post:
        kwargs.pop("postinst")

    pkg_rpm(
        name = name,
        summary = kwargs["description"],
        srcs = ["%s_configs" % name, "%s_systemds" % name, "%s_execs" % name],
        target_compatible_with = ["@platforms//os:linux"],
        package_file_name = "{package}_{file_name_version}_{architecture}.rpm",
        package_variables = ":package_file_naming_" + name,
        package_name = package,
        release = "%autorelease",
        version_file = ":%s_version" % name,
        requires = deps,
        post_scriptlet_file = post,
        **kwargs
    )

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
            "@platforms//cpu:armv7": "armel",
            "@platforms//cpu:s390x": "s390x",
            # Note: some rules_go toolchains don't (currently) seem to map (cleanly) to @platforms//cpu.
            # "@platforms//cpu:ppc": "ppc64",
            # "@platforms//cpu:ppc64le": "ppc64le",
        })

    name_elems(
        name = "package_file_naming_" + name,
        file_name_version = "@@//:file_name_version",
        architecture = kwargs["architecture"],
        package = kwargs["package"],
    )

    pkg_deb(
        name = name,
        data = data,
        target_compatible_with = ["@platforms//os:linux"],
        package_file_name = "{package}_{file_name_version}_{architecture}.deb",
        package_variables = ":package_file_naming_" + name,
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

# A copy file implmentation that derives its output from its (configuable) input. This is used to
# bring files made by an external dependency build into the local build.
def _copy_in_impl(ctx):
    src_path = ctx.file.src.path
    dst_name = ctx.file.src.basename
    out_file = ctx.actions.declare_file(dst_name)
    ctx.actions.run_shell(
        inputs = [ctx.file.src],
        outputs = [out_file],
        arguments = [
            src_path,
            out_file.path,
        ],
        command = "cp -f $1 $2",
    )
    return DefaultInfo(files = depset([out_file]))

_copy_in = rule(
    implementation = _copy_in_impl,
    executable = False,
    attrs = {
        "src": attr.label(
            mandatory = True,
            allow_single_file = True,
            doc = "The label of the file to copy in.",
        ),
    },
)

def scion_pkg_ipk(name, **kwargs):
    """
    The package labeled @openwrt_<target_arch>_SDK//:<name> is built and copied to
    ./<basename of src file>.

    @openwrt_<target_arch>_SDK is an external dependency. Their build file is BUILD.external.bazel.
    For the build of the package to be possible, the openwrt_<target_arch>_SDK tree must be
    imported by way of an http_archive directive in //WORKSPACE.

    target_arch is the specific target cpu as understood by the openwrt toolchain. It is mapped
    from the cpu as is understood by bazel plaform (as in --platforms=[...]) for which we build.
    """
    _copy_in(
        name = name,

        # The final target and file names cannot be evaluated before action time. So we have to pass
        # the entire unresolved select expression. There may be ways around this, but just as ugly.
        src = select({
            "@platforms//cpu:x86_64": "@openwrt_x86_64_SDK//:" + name,
        }),
        **kwargs
    )

def _basename(s):
    return s.split("/")[-1]
