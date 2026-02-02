# Border Router Forwarding Priority Test

The test ensures that the priorities at the border router work as expected:
this means, that the packets flagged as priority are forwarded without losses,
with some caveats:
- All packets incoming to an AS can be read and processed by the border router.
- Any possible packet drops are due to lack of bandwidth on the egress interface
    (this is a consequence of the previous point).
- Priority traffic does not exceed the capacity of the egress interface.

Under these conditions, the packet prioritization done in the border router should
prevent any packet drops for priority traffic.

The test checks for BFD packet drops, which are always flagged as priority,
in a controlled scenario:
- The border router has enough processing capacity:
    - The test will limit the capacity of the network interfaces to a small bandwidth.
    - The test uses the very small `Tiny.topo` topology,
        which needs a very small number of processes, which in turn do not consume much CPU.
- The priority traffic does not exceed the egress capacity:
    - The amount of BFD traffic is configured in the test to be very small.

This test uses the tiny topology:
```text
                        +-----------------+
                        |                 |
                        | AS 1-ff00:0:110 |
                        |                 |
                        +-----------------+
                                 |
            +--------------------+--------------------+
            |                                         |
            | <---- capped interface                  |
    +-----------------+                      +-----------------+
    |                 |                      |                 |
    | AS 1-ff00:0:111 |                      | AS 1-ff00:0:112 |
    |                 |                      |                 |
    |   tester-111    |                      |   tester-112    |
    |                 |                      |                 |
    +-----------------+                      +-----------------+
```

## Components of the test
Out of the box from the tiny topology we have:
- 4 SCION border routers (the AS 1-ff00:0:110 has two BRs).
- 3 SCION control services.
- 3 SCION dispatchers for the control services.
- 3 SCION daemons.
- 3 tester applications.
- 3 SCION dispatchers for the tester applications.

For a total of 19 docker containers.
Additionally, the tiny topology defines 5 networks. Here is the list and the containers using them:
- scn_000: Inter-AS 110 <-> 111
    - `br-1 @ 1-ff00:0:110`
    - `br-1 @ 1-ff00:0:111` <--- This is the one whose capacity we want to limit.
- scn_001: Intra-AS 110
    - `br-1 @ 1-ff00:0:110`
    - `br-2 @ 1-ff00:0:110`
    - `daemon @ 1-ff00:0:110`
    - `disp-cs-1 @ 1-ff00:0:110`
    - `disp-tester @ 1-ff00:0:110`
- scn_002: Intra-AS 111
    - `br-1 @ 1-ff00:0:111`
    - `daemon @ 1-ff00:0:111`
    - `disp-cs-1 @ 1-ff00:0:111`
    - `disp-tester @ 1-ff00:0:111`
- scn_003: Inter-AS 110 <-> 112
    - `br-2 @ 1-ff00:0:110`
    - `br-1 @ 1-ff00:0:112`
- scn_004: Intra-AS 112
    - `br-1 @ 1-ff00:0:112`
    - `daemon @ 1-ff00:0:112`
    - `disp-cs-1 @ 1-ff00:0:112`
    - `disp-tester @ 1-ff00:0:112`

The test requires a sender binary (automatically built if run with bazel).
It is used at the tester-111 container to blast tester-112 with SCION UDP packets,
without any kind of flow control.
The regular `scion ping` does not work here, as it paces itself if responses are not received.


## How to run the demo test

1. [Set up the development environment](https://docs.scion.org/en/latest/build/setup.html)
2. `bazel test --test_output=streamed --cache_test_results=no //demo/router_priority:test`
