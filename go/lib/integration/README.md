# Go Integration Tests

Integration tests in go are standalone binaries that can be run.
The convention is that binaries should end in _integration.
We do this by putting the main of integration test in a package named *_integration.
After building the integration test binaries end up in `./bin`

All integration tests assume the topology is running (`scion.sh run`)

To run the pingpong integration test do:
```
$ ./scion.sh build
$ ./scion.sh start
$ ./bin/pp_integration
```

## Implementation of your own integration test

* An integration test should be a standalone binary, i.e. should have a main method.
* The binary should be named *_integration.
* It should exit (`os.Exit()`) with 0 on success and with a non-zero value on error.
* The `Integration` interface and the methods in integration should be used to implement the test.
* An example can be found in `go/examples/pingpong/pp_integration`.
