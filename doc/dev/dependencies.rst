.. _external-dependencies:

Dependencies
============

Go
--
Go dependencies are managed as `Go modules <https://golang.org/ref/mod>`_.
Dependencies are controlled by the ``go.mod`` file, and cryptographic hashes of
the dependencies are stored in the ``go.sum`` file.

When building with Bazel, external dependencies are managed with ``go_deps``
extension in the MODULES file.
All direct Go dependencies of the module have to be listed explicitly.
The @rules_go//go target automatically updates the ``use_repo`` call
whenever the ``go.mod`` file changes by using ``bazel mod tidy``.

Workflow to modify dependencies
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To add/remove or update dependencies:

1. Modify ``go.mod``, manually or using e.g. ``bazel run @rules_go//go get``.
2. ``bazel mod tidy``
3. ``make licenses``, to update the licenses with the new dependency
4. ``make gazelle``, to update the build files that depend on the newly added dependency

Python
^^^^^^

The Python dependencies are listed in ``requirements.txt`` files. They are generated with Bazel from the
corresponding ``requirements.in`` files.

The Python dependencies are listed in `tools/env/pip3/requirements.txt
<https://github.com/scionproto/scion/blob/master/tools/env/pip3/requirements.txt>`__
and `tools/lint/python/requirements.txt
<https://github.com/scionproto/scion/blob/master/tools/lint/python/requirements.txt>`__.
These files is generated from the corresponding ``requirements.in`` by Bazel. Only
direct dependencies need to be listed; the transitive dependencies are inferred.
The exact command to update ``requirements.txt`` is described in a comment in
the file's header.
