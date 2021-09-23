# Managing yarn dependencies with bazel

To update the YARN dependencies in this directory:

1. `cd` into the directory.
1. run your yarn command:

   - bazel run @nodejs//:yarn upgrade
   - bazel run @nodejs//:yarn install ...
   - etc. see [yarn docs](https://classic.yarnpkg.com/en/docs/usage/) for more details.

To list bazel targets from this specific yarn module: `bazel query @spec_npm//...`

More information can be found in [rules_nodejs
docs](https://docs.aspect.dev/bazelbuild/rules_nodejs/4.0.0/docs/).
