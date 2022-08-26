.. _Go mocks:

********
Go mocks
********

For some tests it is helpful to mock an interface. The `gomock
<https://github.com/golang/mock>`_ library should be used.

Adding mocked interface
-----------------------

Assume that you want to mock an interface ``Foo`` and ``Bar`` that are defined in the
directory ``go/lib/foo``. First, you need to create the subdirectory
``go/lib/foo/mock_foo``. Inside this subdirectory, we add the build bazel file
``BUILD.bazel``. We need to add a ``gomock`` target in this ``BUILD.bazel`` file for our
interfaces. This would look like the following::

    load("@io_bazel_rules_go//go:def.bzl", "gomock")
    gomock(
        name = "go_default_mock",
        out = "mock.go",
        interfaces = [
            "Foo",
            "Bar",
        ],
        library = "//pkg/foo:go_default_library",
        package = "mock_foo",
    )

For an example, refer to
`this exmaple file <https://github.com/scionproto/scion/blob/master/go/lib/log/mock_log/BUILD.bazel>`_.
For further information on the gomock bazel rules, refer to
`gomock for Bazel <https://github.com/jmhodges/bazel_gomock>`_.

After making the aforementioned changes, we need to run the following
command form the root of the repository::

    make mocks

This will create a mock file; for instance, in the above example this file will be
``/go/lib/foo/mock_foo/mock.go``.

Updating generated mocks
------------------------

One can delete or add new interfaces to the ``BUILD.bazel`` file and then run
``make mocks`` to update the corresponding ``mock.go`` files.
