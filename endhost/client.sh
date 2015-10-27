#!/bin/bash

./client_dispatcher 127.1.19.254 &
PYTHONPATH=../ python3 dummy.py 127.1.19.254 ../gen/ISD1/topologies/ISD1-AD19.json
