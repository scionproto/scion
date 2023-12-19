# SCION

[![Slack chat](https://img.shields.io/badge/chat%20on-slack-blue?logo=slack)](https://scionproto.slack.com)
[![Matrix chat](https://img.shields.io/badge/chat%20on-matrix-blue?logo=matrix)](https://matrix.to/#/#dev:matrix.scion.org)
[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/scionproto/awesome-scion)
[![ReadTheDocs](https://img.shields.io/badge/doc-reference-blue?version=latest&style=flat&label=docs&logo=read-the-docs&logoColor=white)](https://docs.scion.org/en/latest)
[![Go Docs](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/scionproto/scion)
[![Nightly Build](https://badge.buildkite.com/b70b65b38a75eb8724f41a6f1203c9327cfb767f07a0c1934e.svg)](https://buildkite.com/scionproto/scion-nightly/builds/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/scionproto/scion)](https://goreportcard.com/report/github.com/scionproto/scion)
[![GitHub issues](https://img.shields.io/github/issues/scionproto/scion/help%20wanted.svg?label=help%20wanted&color=purple)](https://github.com/scionproto/scion/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22)
[![GitHub issues](https://img.shields.io/github/issues/scionproto/scion/good%20first%20issue.svg?label=good%20first%20issue&color=purple)](https://github.com/scionproto/scion/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)
[![Release](https://img.shields.io/github/release-pre/scionproto/scion.svg)](https://github.com/scionproto/scion/releases)
[![License](https://img.shields.io/github/license/scionproto/scion.svg?maxAge=2592000)](https://github.com/scionproto/scion/blob/master/LICENSE)

Welcome to the open-source implementation of [SCION](http://www.scion-architecture.net)
(Scalability, Control and Isolation On next-generation Networks), a future Internet architecture.
SCION provides route control, failure isolation, and explicit trust information for end-to-end communication.
To find out more about the project, please visit our [documentation site](https://docs.scion.org/en/latest/).

## Installation

Installation packages for Debian and derivatives are available for x86-64, arm64, x86-32 and arm.
These packages can be found in the [latest release](https://github.com/scionproto/scion/releases/latest).
Packages for in-development versions can be found from the [latest nightly build](https://buildkite.com/scionproto/scion-nightly/builds/latest).

Alternatively, "naked" pre-built binaries are available for Linux x86-64 and
can be downloaded from the [latest release](https://github.com/scionproto/scion/releases/latest) or the
[latest nightly build](https://buildkite.com/scionproto/scion-nightly/builds/latest).

### Build from sources

SCION can be built with `go build`. To build all binaries used in a SCION deployment (i.e.
excluding the testing and development tools), run

```sh
CGO_ENABLED=0 go build -o bin ./router/... ./control/... ./dispatcher/... ./daemon/... ./scion/... ./scion-pki/... ./gateway/...
```

The default way to build SCION, however, uses Bazel.
In particular, this allows to run all the tests, linters etc.
Please visit our [documentation site](https://docs.scion.org/en/latest/dev/setup.html) for
instructions on how to set up Bazel and the full development environment.

### Connecting to the SCION Network

Join [SCIONLab](https://www.scionlab.org) if you're interested in playing with SCION in an
operational global test deployment of SCION.

The [awesome-scion](https://github.com/scionproto/awesome-scion#deployments) list contains
pointers to production deployments of SCION.

## Contributing

Interested in contribution to the SCION project? Please visit our
[contribution guide](https://docs.scion.org/en/latest/dev/contribute.html)
for more information about how you can do so.

Join us on our [slack workspace](https://scionproto.slack.com) with this invite link:
[join scionproto.slack.com](https://join.slack.com/t/scionproto/shared_invite/zt-1gtgkuvk3-vQzq3gPOWOL6T58yu45vXg)

## License

[![License](https://img.shields.io/github/license/scionproto/scion.svg?maxAge=2592000)](https://github.com/scionproto/scion/blob/master/LICENSE)
