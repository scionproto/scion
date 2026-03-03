***************
IP/UDP underlay
***************


.. _stack:


Introduction
------------

SCION strongly emphasizes the separation between inter-domain routing and intra-domain forwarding. This allows it to easily reuse existing intra-domain network fabrics to provide connectivity among SCION infrastructure services, routers, and endpoints. To maximize compatibility with current network infrastructures and avoid requiring full inter-domain forwarding tables on internal routers, most implementations encapsulates the SCION header inside a standard UDP/IPv6 or UDP/IPv4 packet. In such case, SCION packets are enclosed within the standard IP/UDP protocol stack:

.. code-block:: text

    +-----------------------------+
    |                             |
    |        Payload (L4)         |
    |                             |
    +-----------------------------+
    |           SCION             |
    +-----------------------------+ <-+
    |            UDP              |   |
    |                             |   | Intra-domain
    +-----------------------------+   | protocol
    |            IP               |   |
    +-----------------------------+   |
    |        Link Layer           |   |
    +-----------------------------+ <-+


Ports Overview
--------------

SCION components rely on a structured port allocation scheme to handle underlay (UDP/IP) and service communications. The following table summarizes the common default ports and their configuration scopes:

+-----------------------------------------+------------------+-----------------+----------------------+-----------------------------------------------------------------------------------------------------------------------------------+
| Description                             | Port Range       | Default Value   | Scope                | Configured in                                                                                                                     |
+=========================================+==================+=================+======================+===================================================================================================================================+
| UDP underlay default port / SCMP Daemon | Fixed            | UDP 30041       | Global all end-hosts | Hardcoded                                                                                                                         |
+-----------------------------------------+------------------+-----------------+----------------------+-----------------------------------------------------------------------------------------------------------------------------------+
| UDP underlay dispatched ports           | any              | UDP 31000-32767 | AS-wide              | :doc:`topology.json <../manuals/common>`                                                                                          |
+-----------------------------------------+------------------+-----------------+----------------------+-----------------------------------------------------------------------------------------------------------------------------------+
| Router Internal Interfaces              | any              | UDP 30100-30199 | Router-wide          | :doc:`topology.json <../manuals/common>`                                                                                           |
+-----------------------------------------+------------------+-----------------+----------------------+-----------------------------------------------------------------------------------------------------------------------------------+
| Router External Interfaces              | any              | UDP 31000-39999 | Link                 | :doc:`topology.json <../manuals/common>`                                                                                          |
+-----------------------------------------+------------------+-----------------+----------------------+-----------------------------------------------------------------------------------------------------------------------------------+
| Control Plane Intra-AS                  | any              | UDP/TCP 30252   | AS-wide              | `Control Port Table <../manuals/control.html#port-table>`_                                                                        |
+-----------------------------------------+------------------+-----------------+----------------------+-----------------------------------------------------------------------------------------------------------------------------------+
| Control Plane Inter-AS                  | any              | Dynamic         | AS-wide        | `Service discovery <https://datatracker.ietf.org/doc/html/draft-dekater-scion-controlplane-15#name-control-service-discovery>`_ |
+-----------------------------------------+------------------+-----------------+----------------------+-----------------------------------------------------------------------------------------------------------------------------------+


Traffic to End-hosts
~~~~~~~~~~~~~~~~~~~~~~~~~~

From routers to endpoints, the SCION UDP/IP underlay generally uses the same destination port in the SCION payload also in the underlay.

In the modern "dispatcherless" design (see :doc:`Router Port Dispatch <../dev/design/router-port-dispatch>`), applications open a UDP/IP underlay socket directly. To ensure that traffic goes to the correct application, the ingress router at the destination AS MUST select the underlay destination port as follows:

* inspects the Layer 4 destination port from the TCP/SCION, UDP/SCION or SCMP Error payload.
* **Dispatched Ports**: If the port falls in the dispatched ports range, forward the packet on the same UDP underlay destination port to the end host.
* **UDP underlay default port**: If the port falls outside the configured range, or if the system is handling legacy fallback traffic* (how does the router determines that?), forwards the packet to the default end-host data port: **30041**.
* **SCMP**: for SCMP informational messages, or if the port cannot be extracted, forward on the default end-host port **30041**.

*Note that historically, SCION end hosts relied on a user-space "dispatcher" process listening on default port UDP 30041 to route incoming packets to the correct application socket (see https://docs.scion.org/en/latest/manuals/dispatcher.html ). 

The SCMP Daemon (``scmpd``) MUST listen on the UDP underlay default port and process and reply to informational SCMP messages, such as echo requests (pings) and traceroutes.


Traffic from End-hosts
~~~~~~~~~~~~~~~~~~~~~~

End-hosts send traffic to the SCION router's Internal Interface address and port. This port must be configured on endpoints via the topology.json file.

STUN Support and NAT Address Discovery
--------------------------------------

End hosts located behind a Network Address Translation (NAT) device face a unique challenge: the source address they encode must be the external IP and port visible to the first-hop border router, rather than their internal local address.

To resolve this, SCION incorporates a :doc:`NAT IP/port discovery mechanism <../dev/design/NAT-address-discovery>` conceptually similar to the STUN (Session Traversal Utilities for NAT) protocol, operating directly between clients and border routers. The border router acts as a detector; when the client sends a discovery request, the border router observes the NAT-mapped IP and port and reports it back to the client.

The end host can then reliably inject this public, border-router-visible IP and port into the SCION source address fields of its outbound packets. This guarantees that return traffic from the remote destination can be successfully routed back through the NAT to the client.

Routers
~~~~~~~

SCION border routers utilize specific underlay ports to process and forward traffic:

* **Internal Interfaces**: Used for intra-AS communication between routers and with end-hosts. A range of ports can be used for multiple interfaces.
* **External Interfaces**: Used for inter-AS links facing neighboring SCION ASes. These can be arbitrarily configured with the neighbor router.

Control Plane Instances
~~~~~~~~~~~~~~~~~~~~~~~

Control plane components require service ports for topology synchronization, beaconing, and PKI tasks:

* **Control Plane Intra-AS**: Control services typically communicate over TCP/IP and UDP/SCION on ports **40000-40099**.
* **Control Plane Inter-AS**: Control plane traffic across AS boundaries relies on QUIC/SCION, with the exact ports dynamically chosen by the service.

Ports are described in https://docs.scion.org/en/latest/manuals/control.html#port-table 


Protocol Stack Summary
--------------------------------------

A visual summary of the SCION overall protocol stack is below:

.. figure:: fig/stack.excalidraw.png

This implementation supports an IP/UDP underlay. Other underlay protocols are in principle possible (e.g., MPLS).
