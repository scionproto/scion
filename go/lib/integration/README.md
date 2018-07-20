# Go Integration Tests

Integration tests in go are standalone binaries that can be run.
The convetion is that binaries should end in _integration.
We do this by putting the main of integration test in a package named *_integration.
After building the integration test binaries end up in `./bin`

All integration tests assume the topology is running (`scion.sh run`)

To run the pingpong integration test do:
```
$ ./scion.sh build
$ ./scion.sh start
$ ./bin/pp_integration
```