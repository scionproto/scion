# Sample Discovery Service Client

This is a sample client that uses the library support for querying
the discovery service. To successfully request topology files,
a server needs to be running. `server.sh` is a simple script
to start an http server.

```
./server.sh topology.json 30084
```

The client application periodically fetches the topology file from
one of the available discovery services. The first topology file
that is received is written to stdout. All subsequent topology
files are simply logged.

The client application has two ways of getting the initial topology
file. Either it is specified through a flag, or the client is provided
with an initial discovery service address to fetch it from.

To provide the topology file, run the following command:
```
discovery_client -topo topology.json
```
The discovery service addresses are fetched from the topology file, 
and the client will periodically request topologies.

To initially fetch the topology file from the discovery service,
run the following command:
```
discovery_client -addr 0-0,[127.0.0.1]:30084
```
The client fetchers the topology from the address to get all 
discovery service instances. Then it periodically fetches the 
topology.

The sample topology contains two discovery service entries. One
on port `30084` and one on port `30085`. Both can be started with
`server.sh`. This allows to test that automatic switching is 
supported by the library.
