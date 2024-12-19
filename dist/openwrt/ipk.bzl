# This build file is layered onto the openwrt build tree which is
# imported as an external dependency.
# When reading, remember that:
# * This used in the context of external/openwrt_<target>_SDK/.
# * The "command" script is *not* sandboxed.

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

# All this replicates the standard openwrt recipe to add and build a new package (one which
# code is already compiled). Two hacks in-there:
#
# * Because the openwrt src tree is full of dangling or circular symlinks, we can't run the
#   packaging steps in a sandbox (bazel can't clone the tree); we have to do it in-place.
# * Because we aren't sandboxed and the Makefiles aren't re-entrant, we can't build more than one
#   package at a time. To achieve that we serialize the packaging of each component by arbitrarily
#   depending on the previous one. For this to work, we have to declare the deps as inputs
#   eventhough we don't use them.

def _ipk_impl(ctx):
    pkg_name = "scion-" + ctx.attr.pkg
    target_arch = ctx.attr.target_arch
    in_deps = ctx.files.deps  # Artificial dep, for serialization.
    in_execs = ctx.files.executables
    in_initds = ctx.files.initds
    in_configs = ctx.files.configs
    in_configsroot = ctx.file.configsroot
    in_overrides = ctx.files.overrides
    in_overridesroot = ctx.file.overridesroot
    sdk_feeds_file = ctx.file._sdk_feeds_file
    version_file = ctx.file.version_file
    vers_name = ctx.attr.file_name_version[BuildSettingInfo].value

    out_file = ctx.actions.declare_file(
        "bin/packages/%s/scion/%s_%s_%s.ipk" % (
            target_arch,
            pkg_name,
            vers_name,
            target_arch,
        ),
    )

    # Generate a Makefile to describe the package. Unfortunately, this goes into <execroot>/bin
    # and does not get copied to <execroot> (something to do with consuming it from a non-sandboxed
    # action?) so the pathname is for documentation only. We'll copy.
    makefile = ctx.actions.declare_file("scion/%s/Makefile" % pkg_name)

    ctx.actions.expand_template(
        template = ctx.file._makefile_template,
        output = makefile,
        substitutions = {
            "%{pkg}": pkg_name,
            "%{execs}": " ".join([e.path for e in in_execs]),
            "%{initds}": " ".join([i.path for i in in_initds]),
            "%{configs}": " ".join([c.path for c in in_configs]),
            "%{configsroot}": in_configsroot.path,
            "%{overrides}": " ".join([c.path for c in in_overrides]),
            "%{overridesroot}": in_overridesroot.path,
        },
        is_executable = False,  # from our perspective
    )

    ctx.actions.run_shell(
        execution_requirements = {
            # Cannot use openwrt in a sandbox. It contains broken and circular symlinks that bazel
            # doesn't know how to copy. The price to pay for ditching the sandbox is that mess-ups
            # are sticky. Also, it seems that we must copy the output to execroot ourselves.
            "no-sandbox": "1",
            "no-cache": "1",
        },
        inputs = in_execs + in_initds + in_configs + in_overrides + in_deps + [makefile, sdk_feeds_file, version_file],
        outputs = [out_file],
        progress_message = "Packaging %{input} to %{output}",
        arguments = [
            sdk_feeds_file.path,  # 1
            pkg_name,  # 2
            makefile.path,  # 3
            out_file.path,  # 4
            version_file.path,  # 5
            target_arch,  # 6
        ],
        command = "&&".join([
            r"PATH=/bin:/sbin:/usr/bin:/usr/sbin",
            r"export PATH",
            r'execroot_abspath="$(pwd)"',
            r'sdk_abspath="${execroot_abspath}/$(dirname ${1})"',
            r"cp -f ${1} ${sdk_abspath}/feeds.conf",
            r'echo "src-link scion ${sdk_abspath}/scion" >> ${sdk_abspath}/feeds.conf',
            r"mkdir -p ${sdk_abspath}/scion/${2}",
            r"cp -f ${execroot_abspath}/${3} ${sdk_abspath}/scion/${2}/Makefile",
            r"cd ${sdk_abspath}",
            r"scripts/feeds update scion",
            r"scripts/feeds install -a -p scion",
            r"make IB=1 defconfig",  # IB=1 bypasses various unnecessary prerequisites
            r"IFS='-' read tag count commit dirty < ${execroot_abspath}/$5",
            r"pkgver=${tag}",
            r'pkgrel=${count}${dirty:+".dirty$(date +%s)"}',
            r"make package/feeds/scion/${2}/compile EXECROOT=${execroot_abspath}" +
            ' PKG_VERSION="${pkgver}" PKG_RELEASE="${pkgrel}"',
            r"cp bin/packages/${6}/scion/${2}_${pkgver}${pkgrel:+-}${pkgrel}_${6}.ipk ${execroot_abspath}/${4}",
        ]),
    )

    return DefaultInfo(files = depset([out_file]))

# This functions gets the Label of one file in the top of SDK tree.
# We need such a file so we can figure the pathname for the top of the SDK file tree.
# We happens that we actually use the feeds config file, so use that. This is computed
# by a function because the tree depends on the target arch. Eventhough this .bzl file
# is loaded by the BUILD file in that particular tree, we can't refer to it implicitly:
# "// refers to the tree where this .bzl file is; not the BUILD that loads it."
def _get_sdk_feeds_file(target_arch):
    return Label("@openwrt_" + target_arch + "_SDK//:feeds.conf.default")

_ipk_pkg = rule(
    implementation = _ipk_impl,
    executable = False,
    attrs = {
        "deps": attr.label_list(),  # Packages built in sequence. Each depend on the previous one.
        "_sdk_feeds_file": attr.label(
            default = _get_sdk_feeds_file,
            allow_single_file = True,
            executable = False,
        ),
        "_makefile_template": attr.label(
            default = "@@//dist/openwrt:package_makefile.tpl",
            allow_single_file = True,
            executable = False,
        ),
        "executables": attr.label_list(
            default = [],
            doc = "The executable files (from the scion build) that are being packaged",
        ),
        "target_arch": attr.string(
            mandatory = True,
            doc = "The target arch for which the package is being made",
        ),
        "initds": attr.label_list(
            default = [],
            allow_files = True,
            doc = "The /etc/init.d/* files that are being packaged (packaged with 'scion-' prefix)",
        ),
        "configs": attr.label_list(
            default = [],
            allow_files = True,
            doc = "The /etc/* config files that are being packaged (packaged exactly as named)",
        ),
        "configsroot": attr.label(
            default = "@@//dist:conffiles",
            allow_single_file = True,
            doc = "The common root (in src tree) of /etc/* config files that are being packaged",
        ),
        "overrides": attr.label_list(
            default = [],
            allow_files = True,
            doc = "The /etc/* config files that are being packaged (packaged exactly as named)",
        ),
        "overridesroot": attr.label(
            default = "@@//dist/openwrt:test_configs",
            allow_single_file = True,
            doc = "The common root (in src tree) of /etc/* config files that are being packaged",
        ),
        "pkg": attr.string(
            mandatory = True,
            doc = "A base name for the resulting package (e.g. 'router')",
        ),
        "file_name_version": attr.label(
            mandatory = True,
            doc = "The version string for the package file name",
        ),
        "version_file": attr.label(
            mandatory = True,
            allow_single_file = True,
            doc = "A file containing the version string for the package manifest",
        ),
    },
)

def ipk_pkg(name, **kwargs):
    target_arch = select({
        "@platforms//cpu:x86_64": "x86_64",
    })

    # _ipk_pkg can only package stuff built for musl_libc. Make sure we don't inadvertantly
    # try to package stuff built for the local platform (for example) and get obscure error
    # messages; or worse, apparent success.
    _ipk_pkg(
        name = name,
        target_arch = target_arch,
        target_compatible_with = ["@@//dist/openwrt:musl_libc"],
        file_name_version = "@@//:file_name_version",
        version_file = "@@//dist:git_version",
        **kwargs
    )
