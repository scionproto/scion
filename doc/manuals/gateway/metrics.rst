Gateway metrics can expose the following set of labels:

- ``remote_isd_as``: The ISD-AS of the remote AS.
- ``remote_ifid``: An interface ID of the remote AS.
- ``policy_id``: The ID identifying a session policy.

Traffic Metrics
---------------

Sent IP packets
^^^^^^^^^^^^^^^

**Name**: ``gateway_ippkt_bytes_sent_total``, ``gateway_ippkts_sent_total``

**Type**: Counter

**Description**: Total bytes and packet count of IP packets sent to remote
gateways.

**Labels**: ``remote_isd_as`` and ``policy_id``

Received IP packets
^^^^^^^^^^^^^^^^^^^

**Name**: ``gateway_ippkt_bytes_received_total``, ``gateway_ippkts_received_total``

**Type**: Counter

**Description**: Total bytes and packet count of IP packets received from remote
gateways.

**Labels**: ``remote_isd_as``

Sent local IP packets
^^^^^^^^^^^^^^^^^^^^^

**Name**: ``gateway_ippkt_bytes_local_sent_total``, ``gateway_ippkts_local_sent_total``

**Description**: Total bytes and packet count of IP packets sent to the local
network, i.e., on the internal interface.

**Labels**: none

.. note::
   In the Anapaya EDGE Gateway this covers only those packets that match one of the configured prefixes.

Received local IP packets
^^^^^^^^^^^^^^^^^^^^^^^^^^

**Name**: ``gateway_ippkt_bytes_local_received_total``, ``gateway_ippkts_local_received_total``

**Description**: Total bytes and packet count of IP packets received from the
local network, i.e., on the internal interface.

**Labels**: none

.. note::
   In the Anapaya EDGE Gateway this covers only those packets that match one of the configured prefixes.

Sent frames
^^^^^^^^^^^

**Name**: ``gateway_frame_bytes_sent_total``, ``gateway_frames_sent_total``

**Type**: Counter

**Description**: Total bytes and packet count of frames sent to remote gateways.
This counts the frames the gateway uses to encapsulate the IP traffic. A frame
can contain a partial, one, or multiple encapsulated IP packets.

**Labels**: ``remote_isd_as`` and ``policy_id``

Received frames
^^^^^^^^^^^^^^^

**Name**: ``gateway_frame_bytes_received_total``, ``gateway_frames_received_total``

**Type**: Counter

**Description**: Total bytes and packet count of frames received from remote
gateways. This counts the frames the gateway uses to encapsulate the IP traffic.
A frame can contain a partial, one, or multiple encapsulated IP packets.

**Labels**: ``remote_isd_as``

Discarded Frames
----------------

**Name**: ``gateway_frames_discarded_total``

**Type**: Counter

**Description**: Counts the number of discarded frames. The ``reason`` label can
be used to distinguish different reasons why frames get discarded. Possible values are:

- ``too_old``: discarded because the received frame was older than what the receive window allows
- ``invalid``: discarded because the received frame was corrupted
- ``duplicate``: discarded because the received frame was a duplicate
- ``evicted``: discarded because a newer frame move the receive window and discarded previously received frames that became too old.

**Labels**: ``remote_isd_as``, ``reason``

Discarded IP Packets
--------------------

**Name**: ``gateway_ippkts_discarded_total``

**Type**: Counter

**Description**: Counts the number of discarded IP packets. The ``reason`` label
can be used to distinguish different reasons why IP packets get discarded.
Possible values are:

- ``invalid``: discarded because the received IP packet was corrupted
- ``no_route``: discarded because there is no route for the IP packet
- ``fragmented``: discarded because the IP packet was fragmented.

**Labels**: ``reason``

I/O errors
----------

Send errors
^^^^^^^^^^^

**Name**: ``gateway_send_local_errors_total`` and ``gateway_send_external_errors_total``

**Type**: Counter

**Description**: Counts the number of errors when sending IP packets to the
network (LAN) and sending frames to the network (WAN).

**Labels**: none

Receive errors
^^^^^^^^^^^^^^

**Name**: ``gateway_receive_local_errors_total`` and ``gateway_receive_external_errors_total``

**Type**: Counter

**Description**: Counts the number of errors when receiving IP packets from the
network (LAN) and receiving frames from the network (LAN).

**Labels**: none

Path Monitoring Metrics
-----------------------

Monitored paths
^^^^^^^^^^^^^^^

**Name**: ``gateway_paths_monitored``

**Type**: Gauge

**Description**: Number of paths being monitored to a given remote AS.

**Labels**: ``remote_isd_as``

Path probes sent
^^^^^^^^^^^^^^^^

**Name**: ``gateway_path_probes_sent``

**Type**: Counter

**Description**: Number of path probes being sent.

**Labels**: ``remote_isd_as``

Path probe replies received
^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Name**: ``gateway_path_probes_received``

**Type**: Counter

**Description**: Number of replies to the path probes being received.

**Labels**: ``remote_isd_as``

Available session paths
^^^^^^^^^^^^^^^^^^^^^^^

**Name**: ``gateway_session_paths_available``

**Type**: Gauge

**Description**: Number of paths to a remote AS per session policy. The
``status`` label indicates the status of the path. Possible values are
``rejected`` ``alive``, and ``timeout``.

**Labels**: ``remote_isd_as``, ``policy_id``, ``status``

Session Monitoring Metrics
--------------------------

Session probes
^^^^^^^^^^^^^^

**Name**: ``gateway_session_probes``

**Type**: Counter

**Description**: Number of probes sent to a remote AS per session id.

**Labels**: ``remote_isd_as``, ``policy_id``, ``session_id``

Session probe replies
^^^^^^^^^^^^^^^^^^^^^

**Name**: ``gateway_session_probe_replies``

**Type**: Counter

**Description**: Number of probes from a remote AS per session id.

**Labels**: ``remote_isd_as``, ``policy_id``, ``session_id``

Session is healthy
^^^^^^^^^^^^^^^^^^

**Name**: ``gateway_session_is_healthy``

**Type**: Gauge

**Description**: Healthiness flag to a remote AS per session ID. The
session is ephemeral so it is recommended to use after aggregating
per ``remote_isd_as`` and ``policy_id``.

**Labels**: ``remote_isd_as``, ``policy_id``, ``session_id``


Discovery Metrics
-----------------

Remote gateways
^^^^^^^^^^^^^^^

**Name**: ``gateway_remotes``

**Type**: Gauge

**Description**: Number of remote gateways.

**Labels**: ``remote_isd_as``

Remote IP prefixes
^^^^^^^^^^^^^^^^^^

**Name**: ``gateway_prefixes_accepted``, ``gateway_prefixes_rejected``

**Type**: Gauge

**Description**: Number of accepted/rejected remote IP prefixes.

**Labels**: ``remote_isd_as``

Advertised IP prefixes
^^^^^^^^^^^^^^^^^^^^^^

**Name**: ``gateway_prefixes_advertised``

**Type**: Gauge

**Description**: Number of advertised IP prefixes.

**Labels**: ``remote_isd_as``
