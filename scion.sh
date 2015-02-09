#!/bin/bash
# execute all scripts to add ip aliases for scion networks


if [ $1 == "init" ]; then
    echo "compile crypto library"
    cd lib/crypto/python-tweetnacl-20140309/
    sh do
elif [ $1 == "topology" ]; then
    echo "create topology, configuration and execution  files"
    cd topology/
    PYTHONPATH=../ python3 generator.py
elif [ $1 == "setup" ]; then
    echo "add ip alias for ISDs and ADs"
    for d in topology/ISD*; do
        for f in $d/setup/*; do
            sudo bash $f
        done
    done
elif [ $1 == "run" ]; then
    echo "run network"
    cd infrastructure/
    for d in ../topology/ISD*; do
        for f in $d/run/*; do
            bash $f
        done
    done
elif [ $1 == "stop" ]; then
    echo "stop scion infra's run"
    sudo killall screen
elif [ $1 == "clean" ]; then
    echo "flush all the ip alias of lo (check \"ip addr\" to confirm the addr is flushed)"
    {    
    sudo ip addr flush dev lo
    sudo ip addr add 127.0.0.1/8 dev lo
    } &> /dev/null
else
    echo "only topology, setup, run, stop, and clean are available"
fi

