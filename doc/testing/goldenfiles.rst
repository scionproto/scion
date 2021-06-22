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
