
# This build file is layered onto the openwrt build tree which is
# imported as an external dependency. It is a shell script with
# basel hooks. So, remember that it used in the context of
# external/openwrt_SDK/.

def _ipk_impl(ctx):
    pkg_name = ctx.attr.pkg
    in_file = ctx.file.component
    out_file = ctx.actions.declare_file(
        "bin/packages/x86_64/scion/%s_1.0-1_x86_64.ipk" % pkg_name)
    sdk_feeds_file = ctx.file._sdk_feeds_file

    # Generate a Makefile to describe the package
    makefile = ctx.actions.declare_file("Makefile")

    ctx.actions.expand_template(
        template = ctx.file.Makefile_template,
        output = makefile,
        substitutions = {
            "%{pkg}": pkg_name,
            "%{component}": in_file.path,
        },
        is_executable = False,
    )

    print("Input: ", in_file.path, "Output: ", out_file.path) 
    ctx.actions.run_shell(
        execution_requirements = {
            # Cannot realistically use a non-basel project in a sandbox.
            # It would require declaring the whole tree as a input and copying it.
            # Side effect is that mess-ups are sticky.
            "no-sandbox": "1",
        },
        inputs = [in_file, makefile, sdk_feeds_file],
        outputs = [out_file],
        progress_message = "Packaging %{input} to %{output}",
        arguments = [
            ctx.file._sdk_feeds_file.path,
            pkg_name,
            makefile.path,
            out_file.path,
        ],
        command = "&&".join([
            r'PATH=/bin:/sbin',
            r'export PATH',
            r'makefile_abspath="$(pwd)/$3"',
            r'output_abspath="$(pwd)/$4"',
            r'cd $(dirname $1)',
            r'cp -f $(basename $1) feeds.conf',
            r'echo "src-link scion $(pwd)/scion" >> feeds.conf',
            r'mkdir -p scion/$2',
            r'cp -f $makefile_abspath scion/$2/Makefile',
            r'scripts/feeds update scion',
            r'scripts/feeds install -a -p scion',
            r'make defconfig',
            r'make package/feeds/scion/$2/compile',
            r'cp bin/packages/x86_64/scion/${2}_1.0-1_x86_64.ipk $output_abspath',
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
        "component": attr.label(
            mandatory = True,
            allow_single_file = True,
            doc = "The component (from the scion build) that is being packaged",
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

