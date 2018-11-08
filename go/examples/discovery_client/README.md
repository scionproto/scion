# Sample Discovery Service Client

This is a sample client that uses the library support for querying
the discovery service. To successfully request topology files,
a discovery service needs to be running. `server.sh`starts a 
simple HTTP server that serves a static topology file.

```
./server.sh path/to/topology.json
```

The client application periodically fetches the topology file 
from the discovery service. The first topology file that is 
received is written to stdout. All subsequent topology
files are simply logged.

The client application has two ways of getting the initial topology
file. Either it is specified through a flag, or the client is provided
with an initial discovery service address to fetch it from.

To provide the topology file, run the following command:
```
discovery_client -topo topology.json
```
The discovery service addresses are read from the topology file, 
and the client will periodically request topologies.

To initially fetch the topology file from the discovery service,
run the following command:
```
discovery_client -addr [127.0.0.1]:30084
```

To test automatic switching by the library, `./server.sh` can be
supplied with a topology file that contains multiple discovery
service entries. By default, the address and port of the first
entry in the file are used. The script can be instructed to use
a specific entry:
```
./server.sh path/to/topology.json 2
```
This will start an http server that listens on the address
and port of the second entry in the topology file.

