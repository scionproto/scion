
Acceptance testing framework
============================

To add an acceptance test, create a new `xxx_acceptance` folder in
`/acceptance`, with `xxx` replaced by the name of your test.

The folder must contain a `test.sh` file, which must define the following elements:
* A `TEST_NAME` variable, which matches the name of the folder.
* A `test_setup` function, which takes no arguments and will be executed by the
  framework at the start of the test. If the return value of the function is
  non-zero, the test is aborted.
* A `test_run` function, which takes no arguments and contains the test itself
  (including assertions). If the return value of the function is non-zero, the
  test is failed.
* A `test_teardown` function, which takes no arguments and contains cleanup to
  be performed at the end of the test.

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

Note that `acceptance/ctl` will not save artifacts on its own, and all output
is dumped on the console.
