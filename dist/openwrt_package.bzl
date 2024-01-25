
# This build file is layered onto the openwrt build tree which is
# imported as an external dependency. It is a shell script with
# basel hooks. So, remember that it used in the context of
# external/openwrt_SDK/.

def _ipk_impl(ctx):
    pkg_name = ctx.attr.pkg
    in_execs = ctx.files.executables
    in_initds = ctx.files.initds
    in_configs = ctx.files.configs
    in_configsroot = ctx.file.configsroot
    version = "1.0" # for now
    release = "8" # for now
    out_file = ctx.actions.declare_file(
        "bin/packages/x86_64/scion/%s_%s-%s_x86_64.ipk" % (pkg_name, version, release))
    sdk_feeds_file = ctx.file._sdk_feeds_file

    # Generate a Makefile to describe the package. Unfortunately, this goes into <execroot>/bin
    # and does not get copied to <execroot> so the pathname is for documentation only. We'll copy.
    makefile = ctx.actions.declare_file("scion/%s/Makefile" % pkg_name)

    ctx.actions.expand_template(
        template = ctx.file.Makefile_template,
        output = makefile,
        substitutions = {
            "%{pkg}": pkg_name,
            "%{version}": version,
            "%{release}": release,
            "%{exec}": in_execs[0].path,  # Naming issue with multiple execs; only one name: pkg_name.
            "%{initds}": " ".join([i.path for i in in_initds]),
            "%{configs}": " ".join([c.path for c in in_configs]),
            "%{configsroot}": in_configsroot.path,
        },
        is_executable = False, # from our perspective
    )

    print("Input: ", in_execs, in_initds, in_configs, "Output: ", out_file.path) 
    ctx.actions.run_shell(
        execution_requirements = {
            # Cannot realistically use a non-basel project in a sandbox.
            # It would require declaring the whole tree as an input, causing it to be copied.
            # The price to pay for ditching the sandbox is that mess-ups are sticky.
            "no-sandbox": "1",
            "no-cache": "1",
        },
        inputs = in_execs + in_initds + in_configs + [makefile, sdk_feeds_file],
        outputs = [out_file],
        progress_message = "Packaging %{input} to %{outputs}",
        arguments = [
            ctx.file._sdk_feeds_file.path,
            pkg_name,
            makefile.path,
            out_file.path,
            version,
            release,
        ],
        command = "&&".join([
            r'PATH=/bin:/sbin:/usr/bin:/usr/sbin',
            r'export PATH',
            r'execroot_abspath="$(pwd)"',
            r'sdk_abspath="$execroot_abspath/$(dirname $1)"',
            r'cp -f $1 $sdk_abspath/feeds.conf',
            r'echo "src-link scion $sdk_abspath/scion" >> $sdk_abspath/feeds.conf',
            r'mkdir -p $sdk_abspath/scion/$2',
            r'cp -f $execroot_abspath/$3 $sdk_abspath/scion/$2/Makefile',
            r'cd $sdk_abspath',
            r'scripts/feeds update scion',
            r'scripts/feeds install -a -p scion',
            r'make defconfig',
            r'make package/feeds/scion/$2/compile EXECROOT=$execroot_abspath',
            r'cp bin/packages/x86_64/scion/${2}_${5}-${6}_x86_64.ipk $execroot_abspath/$4',
        ]),
    )

    return DefaultInfo(files = depset([out_file]))

ipk_pkg = rule(
    implementation = _ipk_impl,
    executable = False,

    attrs = {
        "_sdk_feeds_file": attr.label(
            default = Label("@openwrt_SDK//:feeds.conf.default"),
            allow_single_file = True,
            executable = False,
        ),
        "Makefile_template": attr.label(
            default = "@@//dist:openwrt_pkg_makefile.tpl",
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
            doc = "The /etc/init.d/* files that are being packaged",
        ),
        "configs": attr.label_list(
            mandatory = True,
            allow_files = True,
            doc = "The /etc/* config files that are being packaged",
        ),
        "configsroot": attr.label(
            mandatory = True,
            allow_single_file = True,
            doc = "The common root (in src tree of /etc/* config files that are being packaged",
        ),
        "pkg": attr.string(
            mandatory = True,
            doc = "The base name of the resulting package",
        ),
        "args": attr.string_list(
            default = [""],
        ),
    },
)

def _basename(s):
    return s.split("/")[-1]

