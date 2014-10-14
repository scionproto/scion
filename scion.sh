#!/bin/bash
# execute all scripts to add ip aliases for scion networks

if [ $1 == "topology" ]; then
    echo "create topology, configuration and execution  files"
    bash ./topo-gen.sh
elif [ $1 == "setup" ]; then
    echo "add ip alias for ISDs and ADs"
    sudo bash ./setup.sh
elif [ $1 == "run" ]; then
    echo "run network"
    bash ./run.sh
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

