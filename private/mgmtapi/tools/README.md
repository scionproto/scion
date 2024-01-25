# Web Dependencies

This directory contains the web dependencies for the management API tooling.

To reflect changes in the `package.json` file in the `pnpm-lock.yaml` run the
following command (from the workspace root directory):

```bash
bazel run -- @pnpm//:pnpm --dir $PWD/private/mgmtapi/tools install --lockfile-only
```

To update dependencies in the `pnpm-lock.yaml` file run the following command
(from the workspace root directory):

```bash
bazel run -- @pnpm//:pnpm --dir $PWD/private/mgmtapi/tools update --lockfile-only
```
