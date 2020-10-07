# Delve dependencies for docker containers

This directory contains a go.mod file that is used to generate bazel dependencies for delve, so that
we can bundle the delve binary in docker containers.

The go mod file was manually created using:

```sh
go mod init github.com/scionproto/scion/docker/dlv
go get github.com/go-delve/delve@v1.5.0
```

To update the dependency use `go get` to get the new version then update the bazel file with:

```sh
bazel run //:gazelle -- update-repos -from_file=docker/dlv/go.mod -to_macro=dlv_deps.bzl%dlv_repositories
```
