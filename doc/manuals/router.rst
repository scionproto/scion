******
Router
******

Port table
==========

+---------------------------+----------------+--------------+-----------------------------+
|    Description            | Transport      | Port(s)      | Application protocol        |
+---------------------------+----------------+--------------+-----------------------------+
| Underlay data-plane       | UDP            | 30042-30051  | none                        |
+---------------------------+----------------+--------------+-----------------------------+
| Monitoring                | TCP            | 30442        | HTTP/2                      |
+---------------------------+----------------+--------------+-----------------------------+

Metrics
=======

Metrics can expose any combination of the following set of labels:

- ``interface``: The SCION Interface ID of the interface (e.g., ``4``, ``internal``).
- ``neighbor_isd_as``: The ISD-AS of the neighboring router from which this packet
  was received. This label is set to the local ISD-AS for internal interfaces.
- ``isd_as``: The local ISD-AS to which this interface belongs (note that in a
  multi-ISD environment a router can belong to multiple ISD-ASes, but an interface
  can only belong to one).
- ``sibling``: A human-readable description of the sibling router (e.g. ``br1-ff_00_5-2``).

Interface state
---------------

**Name**: ``router_interface_up``

**Type**: Gauge

**Description**: 1 if the router in the remote AS is reachable, 0 otherwise.

**Labels**: ``interface``, ``isd_as`` and ``neighbor_isd_as``.

Connectivity to sibling router instances
----------------------------------------

**Name**: ``router_sibling_reachable``

**Type**: Gauge

**Description**: 1 if a sibling router instance within the local AS is reachable.

**Labels**: ``sibling`` and ``isd_as``.

Input/output bytes total
------------------------

**Name**: ``router_input_bytes_total``, ``router_output_bytes_total``

**Type**: Counter

**Description**: Total number of bytes received/sent by the router. This
only includes data-plane bytes. Bytes received/sent by the Dispatcher on the
local system (if any) are not counted in this number. The underlay header bytes
are not included in this number.

**Labels**: ``interface``, ``isd_as`` and ``neighbor_isd_as``.

Input/output packets total
--------------------------

**Name**: ``router_input_pkts_total``, ``router_output_pkts_total``

**Type**: Counter

**Description**: Total number of packets received/sent by the router.
This only includes data-plane packets. Packets received/sent by the Dispatcher on the
local system (if any) are not counted in this number.

**Labels**: ``interface``, ``isd_as`` and ``neighbor_isd_as``.

Dropped packets total
---------------------

**Name**: ``router_dropped_pkts_total``

**Type**: Counter

**Description**: Total number of packets dropped by the router.
This metric reports the number of packets that were dropped because of errors.

**Labels**: ``interface``, ``isd_as`` and ``neighbor_isd_as``.

BFD state changes (inter-AS)
----------------------------

**Name**: ``router_bfd_state_changes_total``

**Type**: Counter

**Description**: Total number of BFD state changes in a BFD session with a
router in a different AS.

**Labels**: ``interface``, ``isd_as`` and ``neighbor_isd_as``.

BFD state changes (intra-AS)
----------------------------

**Name**: ``router_bfd_sibling_state_changes_total``

**Type**: Counter

**Description**: Total number of BFD state changes in a BFD session with a
router in the local AS.

**Labels**: ``interface``, ``isd_as`` and ``neighbor_isd_as``.

BFD packets sent/received (inter-AS)
------------------------------------

**Name**: ``router_bfd_sent_packets_total``, ``router_bfd_received_packets_total``

**Type**: Counter

**Description**: Number of BFD packets sent to, respectively received from, the
router in a different AS.

**Labels**: ``interface``, ``isd_as`` and ``neighbor_isd_as``.

.. note::

   Not currently supported by the ``router``.

BFD packets sent/received (intra-AS)
------------------------------------

**Name**: ``router_bfd_sent_sibling_packets_total``, ``router_bfd_received_sibling_packets_total``

**Type**: Counter

**Description**: Number of BFD packets sent to, respectively received from, the
router in the local AS.

**Labels**: ``sibling`` and ``isd_as``.

.. note::

   Not currently supported by the ``router``.

Service instance count
----------------------

**Name**: ``router_service_instance_count``

**Type**: Gauge

**Description**: Number of service instances known by the data plane. The router
monitors the reachability of control and discovery service instances. Instances
are dynamically added and removed from the data plane based on their
reachability. Packets with an svc address as destination are sent to any
instance known by the data plane.

**Labels**: ``service`` and ``isd_as``.

Service instance changes total
------------------------------

**Name**: ``router_service_instance_changes_total``

**Type**: Counter

**Description**: Number of total service instance changes. Both addition and
removal of a service instance is accumulated.

**Labels**: ``service`` and ``isd_as``.

HTTP API
========

The HTTP API is exposed by the ``posix-router`` and the ``router`` control-plane application.
The IP address and port of the HTTP API is taken from the ``metrics.prometheus`` configuration
setting.

The HTTP API does not support user authentication or HTTPS. Applications will want to firewall
this port or bind to a loopback address.

The ``router`` and ``posix-router`` currently only support the :ref:`common HTTP API <common-http-api>`.
