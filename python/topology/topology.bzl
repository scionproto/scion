# Generates a tar with all the files generate by topogen.
#   name: name of the rule
#   src: input topology file
#   out: the output tar file
#        by default generated from the source file name, e.g. foo.topo.tar
#   disable_tracing: Disable distributed tracing
#   features: A list of features to add
#   loglvl: File logging level: debug|info|error (default "debug")
#   sig: Enable SIG in topology
#   tag: Defines which set of tag images to be used (e.g scion_cs_<tag>)
#   user: Defines 'user id: group id' to be used in docker-compose file
#   no_bfd: Switch off BFD between border routers
#
def topology(
        name,
        src,
        out = None,
        disable_tracing = False,
        features = None,
        loglvl = None,
        sig = False,
        tag = None,
        user = None,
        no_bfd = False):
    if not out:
        out = src + ".tar"

    params = "-d"
    if disable_tracing:
        params += " --disable_tracing "
    if features:
        params += " --features " + ",".join(features)
    if loglvl:
        params += " --loglvl " + loglvl
    if sig:
        params += " --sig"
    if tag:
        params += " --tag " + tag
    if user:
        params += " --user " + user
    if no_bfd:
        params += " --no_bfd"

    cmd = ("$(location //python/topology:topogentar) " +
           "--scion_pki $(location //go/scion-pki) " +
           "--topogen_bin $(location //python/topology:topogen) " +
           "--topo $(location " + src + ") --out $@ --params '" + params + "'")
    native.genrule(
        name = name,
        srcs = [
            src,
            "//scripts/cryptoplayground:crypto_lib.sh",  # needed for topogen.
        ],
        outs = [out],
        cmd = cmd,
        tools = [
            "//python/topology:topogentar",
            "//python/topology:topogen",
            "//go/scion-pki",
            "//tools:docker_ip",
        ],
    )

    bundles = []
    if tag == "debug":
        bundles += ["//docker:debug.tar"]
    else:
        bundles += ["//docker:prod.tar"]
    args = ["$(location :" + name + ")"]
    for bundle in bundles:
        args += ["$(location " + bundle + ")"]
