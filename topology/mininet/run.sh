#!/bin/bash
function killpox {
	for i in $(pgrep -f pox)
	do
		kill $i
	done
}
# kill any pox instances before we get started
killpox
POX_CMD="$(which pox) forwarding.l2_learning"
POX_LOG="logs/pox.log"
if [ $? -eq 1 ]
then
	echo "Can't find pox in $PATH."
	exit 1
fi
$POX_CMD 2>&1 >$POX_LOG &
#wait for pox to start to avoid "can't connect to controller errors"
sleep 1
sudo SUPERVISORD=$(which supervisord) python topology/mininet/topology.py
# kill any remaining pox instances
killpox
