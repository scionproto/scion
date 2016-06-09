#!/bin/bash
rm logs/* && ./scion.sh stop && ./scion.sh run
./supervisor/supervisor.sh stop as2-$1:er2-$1er2-$2
./test/integration/end2end_test.py 
