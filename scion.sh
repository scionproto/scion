#!/bin/bash
# execute all scripts to add ip aliases for scion networks

if [ $1 == "topology" ]; then
    echo "create topology, configuration and execution  files"
	cd topology/
    bash ./topo-gen.sh
elif [ $1 == "setup" ]; then
    echo "add ip alias for ISDs and ADs"
    sudo bash ./topology/setup.sh
    echo "compile crypto library"
    cd lib/crypto/python-tweetnacl-20140309/
    sh do
elif [ $1 == "run" ]; then
    echo "run network"
	cd infrastructure/
    bash ../topology/run.sh
elif [ $1 == "stop" ]; then
    echo "stop scion infra's run"
    sudo killall screen
elif [ $1 == "clean" ]; then
    echo "flush all the ip alias of lo (check \"ip addr\" to confirm the addr is flushed)"
    {    
	sudo ip addr flush dev lo
	} &> /dev/null
else
    echo "only topology, setup, run, stop, and clean are available"
fi

