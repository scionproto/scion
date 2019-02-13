# SCION Testing Framework

All commands are relative to the top-level directory

## Unit tests

### General usage

1. Run all tests: `./scion.sh test`
1. Run all language specific tests: `./scion.sh test py`, `./scion.sh test go`

### Python specific usage
1. Run all tests in a specific file: `./scion.sh test py test/lib/packet/opaque_field_test.py`
1. Run a specific test: `./scion.sh test py test.lib.packet.opaque_field_test:TestHopOpaqueFieldCalcMac`
1. Run a specific test function: `./scion.sh test py test/lib/packet/opaque_field_test.py:TestHopOpaqueFieldCalcMac.test_prev`
1. See which tests are being run: `./scion.sh test py -v`

## Code coverage
To get a html report of the testing coverage, run `./scion.sh coverage`

## Integration Tests
Several integration tests can be found under `python/integration`. Before running any of
those tests, you have to start the infrastructure (`./scion.sh start`).

To run all integration tests run `integration/integration_test.sh`. This will start
the infrastructure, however, it doesn't compile it. If you haven't compiled the infrastructure
yet or made local changes then first run `make`.

### Docker
It's possible to run the entire infrastructure in a docker container. For more information
see `docker/README.md`.

### Per-app Docker
It's possible to run every service instance in its own docker container. When creating the
topology, specify the `-d` flag.

If you want to use `docker-compose` commands, `./tools/dc` might be helpful.

### CI
The SCION project uses Buildkite as its continuous integration platform. To run an approximated
local version of the CI pipeline (does not include acceptance tests), first build a docker image
as described in `docker/README.md` and then run `tools/ci/local`.
