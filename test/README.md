This directory contains unit tests designed to be ran using the [Nose
unittesting framework](http://nose.readthedocs.org/en/latest/index.html).

## Usage
All commands must be run within `tests/` directory.

1. Run all tests: `nosetests3`
1. Run all tests in a specific file: `nosetests3 opaque_field_test.py`
1. Run a specific test: `nosetests3 opaque_field_test.py:TestOpaqueFields.test_equality`
1. See which tests are being run: `nosetests -v`

## Code coverage
To get a html report of the testing coverage, run `./scion.sh coverage` in the
top directory.
