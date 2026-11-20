"""Macro for containerlab-based system tests."""

load("//tools:go.bzl", "go_test")

# _PHASES maps the suffix of a generated phase target to the flag that
# clab.RegisterPhasedTest registers for that phase.
_PHASES = {
    "setup": "-setup",
    "run": "-execute",
    "teardown": "-teardown",
}

# _LAB_ARTIFACTS are the artifacts every lab needs, keyed by the environment
# variable through which clab.Environment finds them.
_LAB_ARTIFACTS = {
    "AWAIT_CONNECTIVITY_BIN": "//testing/clab/cmd/await_connectivity",
    "CLAB_NODE_IMAGE_TAR": "//testing/clab:clab_node.tarball",
    "TESTGEN_BIN": "//testing/clab/cmd/testgen",
}

def clab_system_test(name, args = [], data = [], env = {}, tags = [], **kwargs):
    """Creates a containerlab system test with phased run targets.

    The <name> target runs all phases of the test: setup, execute and
    teardown. Run it with `bazel test`.

    The macro also creates the <name>_setup, <name>_run and <name>_teardown
    targets. Each one runs a single phase of a test that uses
    clab.RegisterPhasedTest, and the lab stays deployed between the phases.
    Invoke them with `bazel run`, e.g. to set up the lab once and then run the
    test against it repeatedly.

    The node image, testgen and await_connectivity are added to the data and
    the environment of the test, for clab.Environment.

    The tests drive the host docker daemon and containerlab. They run without
    a sandbox ("local") and one at a time ("exclusive"). They are "manual",
    because containerlab must be installed on the machine that runs them.

    Args:
        name: name of the test target.
        args: additional arguments for the test binary.
        data: additional data dependencies.
        env: additional environment variables.
        tags: additional tags for the test targets.
        **kwargs: arguments for go_test (srcs, deps, ...).
    """
    data = data + [label for label in _LAB_ARTIFACTS.values() if label not in data]
    env = dict(env)
    for key, label in _LAB_ARTIFACTS.items():
        if key not in env:
            env[key] = "$(rootpath %s)" % label
    system_tags = [
        "exclusive",
        "integration",
        "manual",
    ]
    go_test(
        name = name,
        size = "large",
        args = args,
        data = data,
        env = env,
        local = True,
        tags = tags + system_tags,
        **kwargs
    )
    for suffix, phase_flag in _PHASES.items():
        go_test(
            name = "%s_%s" % (name, suffix),
            timeout = "eternal",
            # The phase targets are made for `bazel run`. Stream the test log
            # and disable the 10 minute default timeout of a directly invoked
            # test binary.
            args = args + [phase_flag, "-test.v", "-test.timeout=0"],
            data = data,
            env = env,
            local = True,
            tags = tags + system_tags,
            **kwargs
        )
