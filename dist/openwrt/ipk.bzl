
# This build file is layered onto the openwrt build tree which is
# imported as an external dependency.
# When reading, remember that:
# * This used in the context of external/openwrt_SDK/.
# * The "command" script is *not* sandboxed.

def _ipk_impl(ctx):
    pkg_name = "scion-" + ctx.attr.pkg
    in_execs = ctx.files.executables
    in_initds = ctx.files.initds
    in_configs = ctx.files.configs
    in_configsroot = ctx.file.configsroot
    in_version_file = ctx.file._version_file
    out_file = ctx.actions.declare_file(
        "bin/packages/x86_64/scion/%s__x86_64.ipk" % pkg_name)
    sdk_feeds_file = ctx.file._sdk_feeds_file

    # Generate a Makefile to describe the package. Unfortunately, this goes into <execroot>/bin
    # and does not get copied to <execroot> (something to do with consuming it from a non-sandboxed
    # action?) so the pathname is for documentation only. We'll copy.
    makefile = ctx.actions.declare_file("scion/%s/Makefile" % pkg_name)

    ctx.actions.expand_template(
        template = ctx.file.makefile_template,
        output = makefile,
        substitutions = {
            "%{pkg}": pkg_name,
            "%{version_file}": in_version_file.path,
            "%{execs}": " ".join([e.path for e in in_execs]),
            "%{initds}": " ".join([i.path for i in in_initds]),
            "%{configs}": " ".join([c.path for c in in_configs]),
            "%{configsroot}": in_configsroot.path,
        },
        is_executable = False, # from our perspective
    )

    ctx.actions.run_shell(
        execution_requirements = {
            # Cannot use openwrt in a sandbox. It contains broken and circular symlinks that bazel
            # doesn't know how to copy. The price to pay for ditching the sandbox is that mess-ups
            # are sticky. Also, it seems that we must copy the output to execroot ourselves.
            "no-sandbox": "1",
            "no-cache": "1",
        },
        inputs = in_execs + in_initds + in_configs + [in_version_file, makefile, sdk_feeds_file],
        outputs = [out_file],
        progress_message = "Packaging %{input} to %{output}",
        arguments = [
            ctx.file._sdk_feeds_file.path,
            pkg_name,
            makefile.path,
            out_file.path,
            in_version_file.path,
        ],
        command = "&&".join([
            r'PATH=/bin:/sbin:/usr/bin:/usr/sbin',
            r'export PATH',
            r'execroot_abspath="$(pwd)"',
            r'sdk_abspath="${execroot_abspath}/$(dirname ${1})"',
            r'cp -f ${1} ${sdk_abspath}/feeds.conf',
            r'echo "src-link scion ${sdk_abspath}/scion" >> ${sdk_abspath}/feeds.conf',
            r'mkdir -p ${sdk_abspath}/scion/${2}',
            r'cp -f ${execroot_abspath}/${3} ${sdk_abspath}/scion/${2}/Makefile',
            r'IFS="-" read tag count commit dirty < ${5}',
            r'rel=${count}${dirty+"-dirty$(date +%s)"}',
            r'cd ${sdk_abspath}',
            r'scripts/feeds update scion',
            r'scripts/feeds install -a -p scion',
            r'make defconfig',
            r'make package/feeds/scion/${2}/compile EXECROOT=${execroot_abspath}' +
             ' PKG_VERSION="${tag}" PKG_RELEASE="${rel}"',
            r'cp bin/packages/x86_64/scion/${2}_${tag}-${rel}_x86_64.ipk ${execroot_abspath}/${4}',
        ]),
    )

    return DefaultInfo(files = depset([out_file]))

ipk_pkg = rule(
    implementation = _ipk_impl,
    executable = False,

    attrs = {
        "_version_file": attr.label(
            default = "@@//dist:git_version",            
            allow_single_file = True,
            executable = False,
        ),
        "_sdk_feeds_file": attr.label(
            default = Label("@openwrt_SDK//:feeds.conf.default"),
            allow_single_file = True,
            executable = False,
        ),
        "makefile_template": attr.label(
            default = "@@//dist/openwrt:package_makefile.tpl",
            allow_single_file = True,
            executable = False,
        ),
        "executables": attr.label_list(
            mandatory = True,
            doc = "The executable files (from the scion build) that are being packaged",
        ),
        "initds": attr.label_list(
            mandatory = True,
            allow_files = True,
            doc = "The /etc/init.d/* files that are being packaged (packaged with 'scion-' prefix)",
        ),
        "configs": attr.label_list(
            mandatory = True,
            allow_files = True,
            doc = "The /etc/* config files that are being packaged (packaged exactly as named)",
        ),
        "configsroot": attr.label(
            mandatory = True,
            allow_single_file = True,
            doc = "The common root (in src tree) of /etc/* config files that are being packaged",
        ),
        "pkg": attr.string(
            mandatory = True,
            doc = "A base name for the resulting package (e.g. 'router')",
        ),
        "version": attr.string(
            default = "1.0",
            doc = "A version string for the package",
        ),
        "release": attr.string(
            default = "1",
            doc = "A release number string for the package",
        ),
    },
)

def _basename(s):
    return s.split("/")[-1]

