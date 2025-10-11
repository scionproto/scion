# STUN Demo
This demo shows how a client can use the STUN server implemented at the border router to determine its public facing IP address and port.
This is useful in case the client is behind a NAT.
The client can subsequently use the determined address as its source address in SCION communication,
to ensure returning packets are correctly delivered back to the client.

Note that this demo handles all STUN requests manually to demonstrate how STUN can be implemented in SCION.
Our goal is to integrate these requests in client libraries so that STUN is performed automatically and transparently
for clients.

The topology used in the demo is based on `tiny.topo`.
An additional network was added to simulate a private network inside AS `1-ff00:0:110`.
An additional docker container was added to act as a NAT between the private network and the AS.
The tester container was moved to within the private network.

```
                +-----------------------+
                |    AS 1-ff00:0:110    |
                |   +---------------+   |
                |   |    Tester     |   |
                |   | (Test-Server) |   |
                |   +---------------+   |
                +-----------------------+
                        |        |
                        |        |
          --------------+        +--------------
          |                                    |
  +--------------------------+   +-------------------------+
  |     AS 1-ff00:0:111      |   |     AS 1-ff00:0:112     |
  |                          |   |                         |
  |                          |   |                         |
  |  +--------------------+  |   |                         |
  |  |  Private Subnet    |  |   |                         |
  |  |    +----------+    |  |   |                         |
  |  |    |    NAT   |    |  |   |                         |
  |  |    +----------+    |  |   |                         |
  |  |          |         |  |   |                         |
  |  |  +---------------+ |  |   |                         |
  |  |  |    Tester     | |  |   |                         |
  |  |  | (Test-Client) | |  |   |                         |
  |  |  +---------------+ |  |   |                         |
  |  +--------------------+  |   +-------------------------+
  +--------------------------+
```

The demo consists of two components: A test client and a test server.
The test client is run within the private network behind the NAT,
and tries to contact the test server, which is located in a different AS.

The demo consists of the following steps:
1. Generate, configure, and start topology
2. Client performs STUN request
3. Client sends SCION packet using determined public address to server
4. Server replies with a SCION packet to client

## Run the Demo

1. [Set up the development environment](https://docs.scion.org/en/latest/build/setup.html)
2. `bazel test --test_output=streamed --cache_test_results=no //demo/stun:test`
