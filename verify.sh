#!/bin/bash
rm -Rf logs/* && ./scion.sh stop && ./scion.sh run
sleep 15
./supervisor/supervisor.sh stop as$1-$2:er$1-$2er$3-$4
sleep 15
# ./test/integration/end2end_test.py 1-13 1-10 
