End hosts without dispatcher
============================

- Author: Matthias Frei.
  Originally proposed by Sergiu Costea.
- Last updated: 2024-03-26
- Status: **Active**
- Discussion at: https://github.com/scionproto/scion/issues/3961

Abstract
--------

Remove the dispatcher, because it causes a variety of problems (some merely implementation problems, others inherent to the design).
SCION applications open a UDP underlay socket directly, and use the corresponding port as the UDP/SCION port.
The router in the destination AS inspects the Layer 4 UDP header and delivers the packet to this port.

Background
----------

The SCION router in the destination AS delivers a packet to the end host at the specified destination address.
The packet is delivered to the end host over UDP/IP, using a fixed end-host data port (30041).
On the end host the packet is then delivered to the appropriate application socket determined by the protocol and port number; only UDP/SCION (and SCMP) are currently supported.
We do not have operating system support for SCION on any platform, so this last step happens in user space, in the "dispatcher".

Applications create UDP/SCION sockets by registering with the dispatcher, establishing a connection to the dispatcher's unix domain socket.
The application then receives and transmits SCION packets (exclusively) over this unix domain socket connection.

The dispatcher also implements other end host stack functionality; in particular, it replies to certain SCMP messages like SCMP Echo (ping).

Problems
^^^^^^^^
This dispatcher is the cause of many issues:

- It is a single point of failure for the SCION network stack of a host. If it goes down, a lot of processes (control service, gateway, tooling) go haywire.
- It lives in user space, moving every forwarded packet from kernel space to user space and back to kernel space, meaning a performance hit.
- It requires a UNIX DOMAIN stream socket, meaning awkward volume mounts in dockerized environments (and awkward resource cleanup/access management).
- It imposes stateful connections that need to be reestablished by client applications if the dispatcher goes down and then up. This has been the cause of many bugs in the past, and the performance impact of the reconnection logic is currently unknown.
- The UNIX DOMAIN socket is a stream, while the data being sent/received are packets. This requires packetization logic and slows forwarding even further.
- It has cost us a lot of time in performance tuning, because we never knew if it is the root cause of performance problems in apps like the SCION IP gateway.
- It is an additional application to configure/deploy/operate on which, crucially, other applications depend on. This has caused headaches in testing where apps need to retry to connect to the dispatcher if it is not up yet, and it led to dependencies in docker-compose.

  This is also a big blocker for deploying multiple separate SCION-enabled applications to a larger variety of platforms.
  For example, on mobile platforms (iOS, Android) there is simply no good way to install and start the dispatcher as a shared dependency of multiple applications.
  Attempts to do so seem to require additional user interactions (in the form of: "please install and enable this other application"), which effectively blocks adoption of SCION use in mobile applications for most average users.

- It masks what applications are actually talking on the network, so traditional firewalls cannot filter based on ports and a simple packet capture is often not sufficient to debug.
- It breaks native network tooling; netstat is ~ useless due to it.

The dispatcher has the following advantages:

- It simulates an end host with full operating system support for SCION, i.e. it's conceptually "correct" and in line with our long-term vision.
- All SCION traffic is tunneled through a single port; this simplifies connectivity matrices and port firewall rules.


Long term vision
^^^^^^^^^^^^^^^^

In the longer term future, all of the functionality of the dispatcher may be
included in the operating system's network stack. Applications open a UDP/SCION
socket directly and the packet dispatching happens in the kernel.
In this scenario, neither the user-space dispatcher nor the proposed workaround is needed.

Proposal
--------

For UDP/SCION, SCION applications open a UDP/IP underlay socket directly, and use the corresponding port as the local UDP/SCION port.
The last SCION router on a path inspects the Layer 4 UDP/SCION destination port to determine the underlay UDP/IP destination port.
For traffic in the local AS, the source end host determines the underlay UDP/IP destination port analogously.

SCMP
^^^^

The same procedure applies for SCMP messages, wherever possible.
For SCMP error messages in response to UDP/SCION packets, the router uses the source port from the quoted offending packet as the underlay destination port.
For SCMP error messages in response to a packet sent from a local end host, the underlay source address is used directly for the error message.

For SCMP :ref:`Echo Requests <echo-request>` and :ref:`Traceroute Requests <traceroute-request>`, SCION applications open a UDP underlay port on the local host and use this port as the Identifier for the request messages.
The requests are sent to the destination end host to the default end-host port 30041.
For SCMP :ref:`Echo Replies <echo-reply>` and :ref:`Traceroute Replies <traceroute-reply>`, the router uses the Identifier field as the destination UDP port.

SCMP Daemon
^^^^^^^^^^^

The remaining functionality of the dispatcher, namely responding to SCMP echo requests, is implemented in a new, very simple "SCMP daemon".
This daemon opens UDP/IP port 30041, where it receives and replies to SCMP Echo requests.
On this port, it will also receive any packet where an appropriate destination port could not be determined (e.g. SCMP error messages for malformed packages).
These events are only logged and counted, but otherwise no appropriate action is possible.

The SCMP daemon is an optional component for end hosts.
If it's not running, the host simply doesn't respond to pings.

Service Addresses
^^^^^^^^^^^^^^^^^

Service destination address resolve to a configured underlay UDP/IP
address, that is, to an IP *and* a (default) port number.

The common use case for service addresses uses a UDP/SCION destination port of 0. In this case, the default underlay port is used.
In case any other destination port is set, it overrides the default. The processing here is analogous to UDP/SCION packets with IP destination address type.

Port Unreachable
^^^^^^^^^^^^^^^^

No SCMP error messages for Port unreachable are sent. On the end host, there is simply no component that could trigger this. Instead, an ICMP port closed message for the UDP/IP port may be triggered.
Given that the dispatcher currently doesn't even send out these SCMP messages, it does not seem to be worth the effort to translate the ICMP message to an SCMP in the router.

Processing rule
^^^^^^^^^^^^^^^

1. The underlay UDP/IP destination port for packets towards the destination end host is chosen as follows:

  - UDP/SCION:

      - SVC destination address type and UDP/SCION destination port is 0: default port for resolved service address
      - Else: UDP/SCION destination port

  - SCMP:

    - :ref:`Echo Reply <echo-reply>`, :ref:`Traceroute Reply <traceroute-reply>`: Identifier field
    - SCMP error messages:

      - If quoted message is UDP/SCION: UDP/SCION source port
      - Error message originating from this router to local end host: underlay source address of offending packet

    - any other, in particular :ref:`Echo Request <echo-request>` and :ref:`Traceroute Request <traceroute-request>`: default end-host port 30041


.. Hint:: This only applies to the ingress-router in the destination AS at the end of the path.
   This does not affect the performance of the high-speed core routers that need to forward huge volumes of data.


Compatibility
^^^^^^^^^^^^^

This change "only" affects the intra-AS forwarding, that is, there is no requirement to coordinate this update between different domains.

Within each AS, we still need to be able to migrate to this new underlay without disrupting the network and without a synchronized update of all the hosts and routers of the AS.
For this, we add two mechanisms:

- the "shim dispatcher"; a simple, stateless UDP packet forwarder running on the updated end hosts, listening on UDP port 30041.
  It inspects the L4 header and forwards all SCION packets to corresponding underlay port on the local host, following the processing rules for the router outlined above.

  The shim dispatcher allows to update individual hosts before updating all of the routers.
  The applications can receive the packets on individual UDP underlay ports and don't need to be aware of whether a packet was forwarded with the local dispatcher or was received directly (from the ingress router or an AS-local source host).

- *conditionally* use the underlay UDP/IP destination port determined with the rules above only for specific *port ranges*.
  These port ranges are AS specific and are included in the topology configuration that end hosts and routers receive.

  As long as there there are no legacy devices/applications using ports in this range, we can update routers without disrupting any old hosts.
  In this port range, we can operate *new* devices/applications *without* support from the shim dispatcher.

  The processing rule above is extended:

  2. If the underlay UDP/IP destination port determined above, i.e. in processing rule 1, is within the port range specified in the topology configuration,
     the packet is sent to that destination port.

     Otherwise, the packet is sent to the default end-host port 30041.

  The port range is configured in the ``topology.json`` file in the following format:

    .. code-block:: yaml

       "dispatched_ports": "<min>-<max>"

  The ``min``, ``max`` values define the range of ports ``[min, max]`` (inclusive).
  The value ``"-"`` explicitly represents an empty range.
  The value ``"all"`` represents the full range (``1-65535``).
  If nothing is configured, the port range defaults to an empty range.

  Applications pick ephemeral ports from this range when opening a socket.


Update procedure
""""""""""""""""

With these mechanisms, the update procedure for an individual AS is:

1. Pick a range for ``dispatched_ports``, and ensure that *no* existing applications are using ports in this range.

   The recommended initial port range for the transition is ``31000-32767``.
   This range is just below the range of ephemeral ports that is assigned by the old dispatcher (32768-65535), ensuring that UDP traffic from legacy end hosts will be unaffected by the port dispatching in the router.
   On legacy hosts, SCMP echo and error requests currently use random IDs, and thus have a low chance (~2.5%) to pick an ID in the range that is port dispatched by the router. As a preparatory change, the range of IDs can reduced, so that there is no intersection.

2. Update devices, **in any order**, without requiring synchronisation:

   a. Update routers individually and enable ``dispatched_ports`` in their ``topology.json``.

   b. Update hosts individually; replace the dispatcher with the shim-dispatcher, rebuild all
      applications based on the updated libraries, and enable ``dispatched_ports`` in their ``topology.json``.

3. Once all (or at least a significant portion of the) routers have been updated, new applications/devices can use ports in the range ``dispatched_ports`` without the shim dispatcher.

   Depending on the types and number of end hosts in the AS and the time it takes for updates to be picked up, this state is may occur for anything from a few minutes to months, until ...

4. Once all hosts have been updated, the ``dispatched_ports`` range can be extended to the entire port range.
   The shim dispatchers can be disabled.

.. Note:: Server applications listening on well-known ports keep using the same ports throughout the
   process. As stated in 1., these ports should not be part of the initial ``dispatched_ports``
   range. When the server is updated (2.b), it needs to make use of the shim dispatcher until
   the port range is extended to the well-known ports, in step 4.

.. Note:: If an AS operator controls all devices in the AS and/or does not plan to allow operating
   new applications/devices without the shim dispatcher, they can pick the empty range in step 1.,
   and state 3. is skipped.


Long term vision compatibility
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Conversely, if our long term vision materializes and we'd have SCION support directly built-in to the operating system's network stack, then this workaround becomes obsolete.
In an optimistic scenario, where there are millions of end hosts running SCION-enabled applications, we can not expect that all devices and applications will be updated to the same level of SCION support within a useful time frame.
Therefore, it will be necessary to be able to gradually phase out the use of this workaround, keeping it around for all the future legacy applications.

.. Note:: In the future, we'd perhaps use a different port, or no longer use UDP/IP but directly IP as the underlay.

The compatibility mechanisms introduced for the update can be reused for this "reverse" transition:

- enable shim dispatcher for services outside of intended ``dispatched_port`` range.
- shrink ``dispatched_ports`` range and configure this on routers and hosts
- on individual hosts: enable OS network stack support and update applications, disable shim dispatcher

.. Note:: It's not quite clear how we can practically coordinate that all relevant hosts have (re-)enabled the shim dispatcher.
   This idea will need more work.
.. Note:: This should not be considered a promise to never break compatibility for end hosts again.


Rationale
---------

Alternative without router support
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Instead of having the router inspect the Layer 4 data to determine the destination underlay port, we could keep this logic on the end host.
Applications open IP/UDP sockets for transmitting packets, as above. To receive packets, a (much simplified) dispatcher process
listens on port 30041 and forwards the packets to localhost:<UDP/SCION destination port>.
This could also be implemented as a port rewrite step for example in an XDP program.

This has some advantages:

- it retains the "correct" end-host model, packets on the wire don't change
- it's an entirely end-host local change
- it also fixes many of the problems listed above related to unix domain sockets, reconnection, etc.

However, this still requires a shared component on the end host if multiple applications want to use SCION concurrently.
For deployment to mobile platforms, in particular, this is still as much of a blocker as the current dispatcher.

Alternative SCMP handling
^^^^^^^^^^^^^^^^^^^^^^^^^

The original proposal did not require the router to inspect SCMP messages.
All SCMP messages would be forwarded to the default end-host port and dispatched from there to the correct application with the SCMP daemon.

Same issue as above; this still requires a shared component on the end-host if applications should be able to receive SCMP messages.
SCMP error messages are crucial for efficient fail-over in SCION. Simply omitting these would not be a good option.

Implementation
--------------

The roadmap would look like the following:

- Prepare:
   - Reduce the range of IDs used for SCMP echo and traceroute requests, so that it matches the range of ports assigned by the legacy dispatcher (32768-65535).

- Add support for dispatched/forwarded port ranges to the topology.json configuration.

  As the topology.json parsing is lenient about unknown keys by default, the updated topology.json file can still be consumed by "legacy" applications.

- Change SCION applications to use native ``net.UDPConn`` instead of ``reliable.Conn``.

  Remove ``reliable`` package and replace functionality of dispatcher with a simple stateless UDP
  packet forwarder. This forwarder listens on UDP port 30041. It inspects the L4 header and forwards
  all SCION packets to corresponding underlay port on the local host, following the processing
  rules for the router outlined above.

  This "new" dispatcher still replies to SCMP echos.

- Add support for the ``dispatched_ports`` range to the router, changing its behavior to set the
  UDP destination underlay port as described above.

- Future release:
   - remove support for old UDP underlay with default port 30041.
     Remove the packet dispatching/forwarding functionality from "dispatcher".
     Only SCMP echo responder remains in dispatcher. Rename to "SCMP Daemon" (scmpd).
   - set suitable default for port range in ``dispatched_ports`` topology configuration.
