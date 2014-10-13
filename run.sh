#!/bin/bash

cd ./infrastructure/
screen -d -m -S bs1 sh -c "PYTHONPATH=../ python3 beacon_server.py 127.0.0.2 ../TD11/topologies/topology1.xml ../TD11/configurations/AD1.conf"
screen -d -m -S ps1 sh -c "PYTHONPATH=../ python3 path_server.py 127.0.0.3 ../TD11/topologies/topology1.xml ../TD11/configurations/AD1.conf"
screen -d -m -S cs1 sh -c "PYTHONPATH=../ python3 cert_server.py 127.0.0.4 ../TD11/topologies/topology1.xml ../TD11/configurations/AD1.conf"
screen -d -m -S bs2 sh -c "PYTHONPATH=../ python3 beacon_server.py 127.0.0.6 ../TD11/topologies/topology2.xml ../TD11/configurations/AD2.conf"
screen -d -m -S cs2 sh -c "PYTHONPATH=../ python3 cert_server.py 127.0.0.7 ../TD11/topologies/topology2.xml ../TD11/configurations/AD2.conf"
screen -d -m -S bs3 sh -c "PYTHONPATH=../ python3 beacon_server.py 127.0.0.9 ../TD11/topologies/topology3.xml ../TD11/configurations/AD3.conf"
screen -d -m -S ps3 sh -c "PYTHONPATH=../ python3 path_server.py 127.0.0.10 ../TD11/topologies/topology3.xml ../TD11/configurations/AD3.conf"
screen -d -m -S cs3 sh -c "PYTHONPATH=../ python3 cert_server.py 127.0.0.11 ../TD11/topologies/topology3.xml ../TD11/configurations/AD3.conf"
screen -d -m -S r1r2 sh -c "PYTHONPATH=../ python3 router.py 127.0.0.12 ../TD11/topologies/topology1.xml ../TD11/configurations/AD1.conf"
screen -d -m -S r2r1 sh -c "PYTHONPATH=../ python3 router.py 127.0.0.13 ../TD11/topologies/topology2.xml ../TD11/configurations/AD2.conf"
screen -d -m -S r2r3 sh -c "PYTHONPATH=../ python3 router.py 127.0.0.14 ../TD11/topologies/topology2.xml ../TD11/configurations/AD2.conf"
screen -d -m -S r3r2 sh -c "PYTHONPATH=../ python3 router.py 127.0.0.15 ../TD11/topologies/topology3.xml ../TD11/configurations/AD3.conf"
