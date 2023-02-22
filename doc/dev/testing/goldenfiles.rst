************
Golden Files
************

As part of our testing suite we leverage golden file testing. All the golden
files that are committed must have a consistent way of updating them.

For this purpose, we define the ``-update`` flag in all the packages that contain
golden file tests.

To update all the golden files, run the following command::

    go test ./... -update

To update a specific package, run the following command::

    go test ./path/to/package -update

The flag should be registered as a package global variable::

    var update = xtest.UpdateGoldenFiles()

**Non-determinism**

Some tests require golden files that are non-deterministic in nature. For
example the private keys and the associated certificates are naturally
non-deterministic. For tests that rely on these golden files, we have a separate
flag ``-update-non-deterministic``.

To update all the non-deterministic golden files, run the following command::

    go test ./... -update-non-deterministic

To update a specific package, run the following command::

    go test ./path/to/package -update-non-deterministic

The flag should be registered as a package global variable::

    var updateNonDeterministic = xtest.UpdateNonDeterminsticGoldenFiles()

