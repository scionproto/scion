# Patches

This directory is home to [gopatch](https://github.com/uber-go/gopatch) patches
that simplify the migration when breaking changes to library packages are
introduced. Furthermore it contains patches to dependencies in subdirectories,
the remainder of this document is only about the patches for migrations.

## Installation

To apply the patches, you need to have access to gopatch. Follow the
[installation instructions](https://github.com/uber-go/gopatch#installation) in
case you do not have gopatch installed yet.

## Applying a patch

To apply a patch, you will need to run the following command:

```txt
cd $YOUR_PROJECT
gopatch -p $SCIONPROTO/patches/$PATCH ./...
```

- `YOUR_PROJECT` is the root of your go project that depends
  on[scionproto/scion](gitub.com/scionproto/scion).

- `SCIONPROTO` is the root of your
  [scionproto/scion](gitub.com/scionproto/scion) clone/fork.

- `PATCH` is the patch that you want to apply.

For more information, consult the [gopatch
readme](https://github.com/uber-go/gopatch#apply-the-patch)
