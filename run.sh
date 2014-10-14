#!/bin/bash

cd ./infrastructure/
screen -d -m -S bs1 sh -c "PYTHONPATH=../ python3 beacon_server.py 127.0.0.2 ../ISD11/topologies/topology1.xml ../ISD11/configurations/AD1.conf"
screen -d -m -S ps1 sh -c "PYTHONPATH=../ python3 path_server.py 127.0.0.3 ../ISD11/topologies/topology1.xml ../ISD11/configurations/AD1.conf"
screen -d -m -S cs1 sh -c "PYTHONPATH=../ python3 cert_server.py 127.0.0.4 ../ISD11/topologies/topology1.xml ../ISD11/configurations/AD1.conf"
screen -d -m -S bs2 sh -c "PYTHONPATH=../ python3 beacon_server.py 127.0.0.6 ../ISD11/topologies/topology2.xml ../ISD11/configurations/AD2.conf"
screen -d -m -S ps2 sh -c "PYTHONPATH=../ python3 path_server.py 127.0.0.7 ../ISD11/topologies/topology2.xml ../ISD11/configurations/AD2.conf"
screen -d -m -S cs2 sh -c "PYTHONPATH=../ python3 cert_server.py 127.0.0.8 ../ISD11/topologies/topology2.xml ../ISD11/configurations/AD2.conf"
screen -d -m -S r1r2 sh -c "PYTHONPATH=../ python3 router.py 127.0.0.9 ../ISD11/topologies/topology1.xml ../ISD11/configurations/AD1.conf"
screen -d -m -S r2r1 sh -c "PYTHONPATH=../ python3 router.py 127.0.0.10 ../ISD11/topologies/topology2.xml ../ISD11/configurations/AD2.conf"
