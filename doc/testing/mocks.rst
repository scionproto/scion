.. _Go mocks:

********
Go mocks
********

For some tests it is helpful to mock an interface. The `gomock
<https://github.com/golang/mock>`_ library should be used. To generate a mock
file and the required Bazel declaration a helper script is used.

Adding a new mock file
----------------------

Assume you want to mock an interface ``Foo`` and ``Bar`` that are defined in the
directory ``go/lib/foo``. To create the mocks and the required bazel files
simply run::

    ./tools/gomocks add --package go/lib/foo --interfaces Foo,Bar

The tool will create two files under ``go/lib/foo/mock_foo``:

- ``mock.go``: contains the mocked interfaces.
- ``BUILD.bazel``: contains the required Bazel rules.

Adding an interface to existing mock
------------------------------------

Unfortunately the current tooling doesn't provide a way to only add a single
interface. You need to look up which interfaces are currently mocked under
``path/to/package/mock_package/BUILD.bazel`` the interfaces should be listed.
Extract the interface list and add your interface, then go through the steps to
add an a new mock file with the interface list you collected.

Verifying mocks are up to date
------------------------------

To verify the mock files in the workspace are up to date run::

    ./tools/gomocks diff

To update the files in the workspace run::

    ./tools/gomocks
