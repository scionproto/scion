# Fuzzing Targets for slayers

This package contains the fuzzing targets for the slayers package.
There are multiple targets defined. The default `Fuzz` target fuzzes
a full SCION packet decoding run. `FuzzLayers` fuzzes individual layers.
Which layer that is fuzzed is determined by the first byte of the input.
Furthermore, there is one target per layer for individual fuzzing.

## Installation

To run fuzzing in your local environment, you need to have `go-fuzz` and
`go-fuzz-build` available in your path.

See: [go-fuzz](https://github.com/dvyukov/go-fuzz)

## Start fuzzing

To start fuzzing, navigate to this directory and run:

```bash
go-fuzz-build --func Fuzz
cp -r ../../testdata corpus
go-fuzz
```

To run a different target, run:

```bash
go-fuzz --func FuzzSCION
```

## Debugging crashers

Crashers will be stored in the `crashers` directory. Per crash, there are
three files. The `.output` file contains the panic information. The `.quoted`
file contains the quoted input data that lead to the crash.

Copy the string of the `.quoted` file and replace the input data in the
appropriate testing function in `fuzz_test.go`. Now, you have a unit test
that panics and can be debugged.
