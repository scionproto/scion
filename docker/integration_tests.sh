#!/bin/bash

set -e
# Run SCION and wait for a start.
./scion.sh run
sleep 5
# Check SCION status before tests.
./scion.sh status
# Run integration tests.
cd test/integration/
PYTHONPATH=../../ python3 end2end_test.py
# Check SCION status after tests.
cd ../../
./scion.sh status
