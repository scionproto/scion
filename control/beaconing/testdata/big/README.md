# Test data generation

It's possible to generate `json` files required for the tests.
For example, the files in `big` directory were generated with this command:
```shell
bazel build //control/beaconing:run_topogen_topology_big
```

This tool uses `topogen`, and then replaces the random interface IDs
that `topogen` generates with the IDs that correspond to the graph defined in
`github.com/scionproto/scion/pkg/private/xtest/graph`.

Since Bazel doesn't allow using a directory as an output of `genrule`,
`write_source_files` accepts either individual files or directories, and
re-generation of the test files is not often needed, the resulting files
are not written to the source tree and can be found in `bazel-out` directory.
For `//control/beaconing:run_topogen_topology_big`, `big.zip` is created there.
You can locate it with this command and then copy it manually:
```shell
bazel cquery //control/beaconing:run_topogen_topology_big --output=files
```
