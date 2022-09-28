# DRKey demo

This demo shows how two hosts can obtain a shared key with the DRKey system.
The "server" side host can locally derive keys for any other host.
The slower "client" side host can fetch its corresponding key from
the DRKey infrastructure running in the control services.

Note that in this demo, no data is transmitted between "client" and "server".
In a practical usage, the server would derive the key for the client's address
after receiving a packet from the client.

The demo consists of the following steps:

1. Enable and configure DRKey and start the topology.
1. Demonstrate the server side key derivation
1. Demonstrate the client side key fetching
1. Compare the keys

## Run the demo

1. [set up the development environment](https://docs.scion.org/en/latest/build/setup.html)
1. `bazel test --test_output=streamed --cache_test_results=no //demo/drkey:test`

Note: this demo works on any SCION network topology. To run the demo on a
different network topology, modify the `topo` parameter in `BUILD.bazel` to
point to a different topology file.
