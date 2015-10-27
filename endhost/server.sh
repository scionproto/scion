#!/bin/bash

./server_dispatcher 127.2.26.254 &
PYTHONPATH=../ python3 dummy.py 127.2.26.254 ../gen/ISD2/topologies/ISD2-AD26.json
