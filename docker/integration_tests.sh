#!/bin/bash

set -e
# Run SCION and wait for a start.
./scion.sh run
echo "Waiting for path propagation, etc..."
sleep 15
# Check SCION status before tests.
./scion.sh status

# Run integration tests.
echo "End2End test"
cd test/integration/
PYTHONPATH=../../ python3 end2end_test.py
# Check SCION status after the test.
cd ../../
./scion.sh status
echo "Traceroute Extension test"
cd test/integration/
PYTHONPATH=../../ python3 cli_srv_ext_test.py
# Check SCION status after the test.
cd ../../
./scion.sh status
