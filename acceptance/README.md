
Acceptance testing framework
============================

To add an acceptance test, create a new `xxx_acceptance` folder in
`/acceptance`, with `xxx` replaced by the name of your test.

The folder must contain a `test` executable, which must support the following arguments:
* `name`, which returns the name of the acceptance test.
* `setup`, which runs the setup portion of the acceptance test. If the return
  value of the application is non-zero, the test is aborted.
* `run`, which runs the test itself (including assertions). If the return value
  of the function is non-zero, the test is considered to have failed.
* `teardown`, which cleans up after the test. If the return value of the
  function is non-zero, the run of the **entire** test suite is aborted.

For an example, see `acceptance/reconnecting_acceptance`.

Basic Commands
==============

To run all defined tests, use:
```
acceptance/run
```

To run only the tests matching a certain regular expression, use:
```
acceptance/run REGEX
```
where REGEX is replaced with a regular expression of your choice.

Manual Testing
==============

To run fine-grained operations for a single test, use one of the following:
```
acceptance/ctl setup TESTNAME
acceptance/ctl run TESTNAME
acceptance/ctl teardown TESTNAME
```
This calls the functions in `acceptance/xxx_acceptance/test.sh` directly,
without any prior setup. This also means docker images are **not** rebuilt,
even if application code has changed.

To run the `ctl` commands above, the environment needs to be built first. To do that, run:
```
acceptance/ctl gsetup
```
This will also rebuild the docker images, taking new code into account.

To run the `setup`, `run` and `teardown` phases of a single test (without gsetup):
```
acceptance/ctl grun TESTNAME
```

Note that `acceptance/ctl` will not save artifacts on its own, and all output
is dumped on the console.
