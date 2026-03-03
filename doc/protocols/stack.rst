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

+--------------------------------+----------------------------------+---------------+------------------------+
| Description                    | Port Range                       | Default Value | Configuration Scope    |
+================================+==================================+===============+========================+
| UDP underlay default port / SCMP Daemon | UDP 30041               | UDP 30041         | Global / End Hosts     |
+--------------------------------+----------------------------------+---------------+------------------------+
| UDP underlay dispatched ports  | UDP any       | UDP 31000-32767   | AS-wide (``topology.json``) |
+--------------------------------+----------------------------------+---------------+------------------------+
| Router Internal Interfaces     | 30100-30199 (UDP/IP)             | 30100         | AS-wide      |
+--------------------------------+----------------------------------+---------------+------------------------+
| Router External Interfaces     | 31000-39999 (UDP/IP)             | 31000         | Link            |
+--------------------------------+----------------------------------+---------------+------------------------+
| Control Plane Intra-AS         | 40000-40099 (TCP/IP & UDP/SCION) | 40000         | AS                     |
+--------------------------------+----------------------------------+---------------+------------------------+
| Control Plane Inter-AS         | Dynamic (QUIC/SCION)             | Dynamic       | AS / Service           |
+--------------------------------+----------------------------------+---------------+------------------------+


Endpoints and Port Mapping
~~~~~~~~~~~~~~~~~~~~~~~~~~

Historically, SCION end hosts relied on a user-space "dispatcher" process listening on default port UDP 30041 to route incoming packets to the correct application socket. In the modern "dispatcherless" design (see :doc:`Router Port Dispatch <../dev/design/router-port-dispatch>`), applications open a UDP/IP underlay socket directly.

When a packet arrives at the destination AS, the ingress router inspects the Layer 4 UDP/SCION destination port to determine the correct underlay UDP/IP destination port for the end host.

* **Dispatched Ports**: A specific port range (e.g., ``31000-32767``) can be configured as ``dispatched_ports`` in the AS's ``topology.json``. If the calculated destination port falls within this range, the router forwards the packet directly to that underlay port on the end host.
* **Default Fallback**: If the port falls outside the configured range, or if the system is handling legacy fallback traffic, the router forwards the packet to the default end-host data port: **30041**.

Routers
~~~~~~~

SCION border routers utilize specific underlay ports to process and forward traffic:

* **Internal Interfaces**: Used for intra-AS communication, defaulting to UDP/IP port **30100** (or the range ``30100-30199`` for multiple interfaces).
* **External Interfaces**: Used for inter-AS links facing neighboring SCION ASes. These are typically assigned UDP/IP ports in the range **31000-39999**.

Control Plane Instances
~~~~~~~~~~~~~~~~~~~~~~~

Control plane components require service ports for topology synchronization, beaconing, and PKI tasks:

* **Intra-AS**: Control services typically communicate over TCP/IP and UDP/SCION on ports **40000-40099**.
* **Inter-AS**: Control plane traffic across AS boundaries relies on QUIC/SCION, with the exact ports dynamically chosen by the service.

For a comprehensive list of default ports, refer to the `Anapaya Port Allocation documentation <https://learn.anapaya.net/docs/technical-documentation/anapaya-appliance/operations/port-allocation/>`_.

SCMP Processing
---------------

The SCION Control Message Protocol (SCMP) handles routing errors and informational requests across the network.

For informational messages like **SCMP Echo Requests (ping)** and **Traceroute Requests**, the traffic is directed to the default end-host port **30041**. A dedicated, lightweight "SCMP Daemon" (``scmpd``) running on the end host listens on this port to process and reply to these requests. This daemon will also catch malformed packets where an appropriate destination port could not be determined.

For SCMP error messages generated in response to an offending UDP/SCION packet, the router parses the quoted offending packet and uses its original source port as the new underlay destination port. This ensures the error message reaches the exact application socket that originated the traffic.

STUN Support and NAT Address Discovery
--------------------------------------

Because SCION is path-aware, packet headers must embed a source address to which return packets can be sent. End hosts located behind a Network Address Translation (NAT) device face a unique challenge: the source address they encode must be the external IP and port visible to the first-hop border router, rather than their internal local address.

To resolve this, SCION incorporates a :doc:`NAT IP/port discovery mechanism <../dev/design/NAT-address-discovery>` conceptually similar to the STUN (Session Traversal Utilities for NAT) protocol, operating directly between clients and border routers. The border router acts as a detector; when the client sends a discovery request, the border router observes the NAT-mapped IP and port and reports it back to the client.

The end host can then reliably inject this public, border-router-visible IP and port into the SCION source address fields of its outbound packets. This guarantees that return traffic from the remote destination can be successfully routed back through the NAT to the client.

Protocol Stack Summary
--------------------------------------

This document provides a visual summary of the SCION overall protocol stack. 

.. figure:: fig/stack.excalidraw.png

This implementation supports an IP/UDP underlay. Other underlay protocols are in principle possible (e.g., MPLS).
