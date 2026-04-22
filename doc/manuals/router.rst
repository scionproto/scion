******
Router
******

:program:`router` is the SCION border router. It forwards SCION packets between
interfaces using an underlay network. Two underlay implementations are available
for the UDP/IP underlay protocol:

* **AF_XDP** (``afxdp``): The default on Linux. Uses
  `AF_XDP sockets <https://docs.kernel.org/networking/af_xdp.html>`_ to bypass the kernel
  network stack, delivering packets directly to userspace achieving higher performance.
  Supports multi-queue NICs for high throughput. Requires Linux 5.9 or later
  and capabilities ``CAP_NET_ADMIN``, ``CAP_NET_RAW``, and ``CAP_BPF``.

* **Inet** (``inet``): Uses ordinary AF_INET UDP sockets. Portable to all
  platforms supported by Go and requires no special privileges. Used as
  a fallback when AF_XDP is unavailable.

The implementation is selected via
:option:`router.preferred_underlays.udpip <router-conf-toml udpip>`.
If the preferred implementation is not available, the router falls back
to any other registered implementation.

.. TODO
   add reference to dataplane section

Command Line Reference
======================

.. program:: router

Synopsis
--------

:program:`router` [:option:`--config \<config.toml\> <router --config>` | :option:`help <router help>` | :option:`version <router version>`]

Options
-------

.. option:: --config <config.toml>

   Specifies the :ref:`configuration file <router-conf-toml>` and starts the router.

.. option:: help, -h, --help [subcommand]

   Display help text for subcommand.

.. option:: version

   Display version information.

.. option:: sample [file]

   Display sample files.

   .. option:: config

      Display a configuration file sample.

.. option:: completion [shell]

   Generate the autocompletion script for :program:`router` for the specified shell.

   Run :option:`router help completion <router help>` for a list of the available shells.

   Run :option:`router help completion [shell] <router help>` for usage information on the
   autocomplete script for a particular shell.

.. _router-envvars:

Environment Variables
---------------------

.. object:: SCION_TESTING_DRKEY_EPOCH_DURATION

   For **testing only**.
   This option relates :option:`features.experimental_scmp_authentication <router-conf-toml features.experimental_scmp_authentication>`.

   Override the global duration for :doc:`/cryptography/drkey` epochs.

   Also applies to the :ref:`control service <control-envvars>`.

   :Type: :ref:`duration <common-conf-duration>`
   :Default: ``24h``

.. envvar:: SCION_TESTING_ACCEPTANCE_WINDOW

   For **testing only**.
   This option relates :option:`features.experimental_scmp_authentication <router-conf-toml features.experimental_scmp_authentication>`.

   Defines the length of the window around the current time for which SCMP authentication timestamps
   are accepted. See :ref:`SPAO specification <spao-absTime>`.

   :Type: :ref:`duration <common-conf-duration>`
   :Default: ``5m``

.. envvar:: GOMAXPROCS

   Specified by the GO runtime. The Go runtime starts a number kernel threads such that the number
   of non-sleeping threads never exceeds ``GOMAXPROCS``. By default ``GOMAXPROCS`` is equal to the
   number of cores in the host. That value can be changed via the ``GOMAXPROCS`` environment
   variable (or programmatically by the application code). See
   `the go runtime documentation <https://pkg.go.dev/runtime#hdr-Environment_Variables>`_
   for more information. One reason to change this is running multiple routers on the same host.
   In such a case, it is best to split the available cores among the routers, lest Go's default
   assumptions causes them to compete for cores and incur futile context switching. This precaution
   is especially useful in performance testing situations.

   :Type: unsigned integer
   :Default: ``all cores``

Configuration
=============

The :program:`router` is configured by two main files.
First, the :ref:`.toml <router-conf-toml>` configures common features like logging and metrics and
specifies the **configuration directory** from which all other configuration files are read.
The second one is :ref:`topology.json <router-conf-topo>`, which contains all the AS information
that the router uses to forward packets.

.. _router-conf-toml:

Router Configuration
--------------------

In addition to the :ref:`common .toml configuration options <common-conf-toml>`, the router
considers the following options.

.. program:: router-conf-toml

.. object:: general

   .. option:: general.id = <string> (Required)

      Identifier for this router.

      This is used to identify which parts of the :ref:`router-conf-topo` file refer to self.
      Thus, ``id`` must match a key in the :ref:`router-conf-topo` files' ``border_routers`` section.

   .. option:: general.config_dir = <string> (Required)

      Path to a directory for loading AS :ref:`topology.json <router-conf-topo>` and :ref:`keys
      <router-conf-keys>`.

      If this is a relative path, it is interpreted as relative to the current working directory of the
      program (i.e. **not** relative to the location of this .toml configuration file).

.. object:: features

   Features is a container for generic, boolean feature flags (usually for experimental or
   transitional features).

   .. option:: features.experimental_scmp_authentication = <bool> (Default: false)

      Enable the :doc:`DRKey-based authentication of SCMPs </dev/design/scmp-authentication>` in the
      router, which is **experimental** and currently **incomplete**.

      When enabled, the router inserts the :ref:`authenticator-option` for SCMP messages.
      For now, the MAC is computed based on a dummy key, and consequently is not practically useful.

.. object:: router

   .. option:: router.receive_buffer_size = <int> (Default: 0)

      The receive buffer size in bytes. 0 means use system default.

   .. option:: router.send_buffer_size = <int> (Default: 0)

      The send buffer size in bytes. 0 means use system default.

   .. option:: router.num_processors = <int> (Default: GOMAXPROCS)

      Number of goroutines started for SCION packets processing.

      These goroutines make the routing decision for the SCION packets by inspecting, validating and
      updating the path information in the packet header. Packets are processed asynchronously from the
      corresponding read/write operations on the individual interface sockets.

      `Goroutines <https://en.wikipedia.org/wiki/Go_(programming_language)#Concurrency:_goroutines_and_channels>`_
      are the Go programming language's light-weight user-space concurrency primitives. Go's runtime
      schedules goroutines on top of a smaller number of kernel threads. The default is to use as
      many packet processors as there are kernel threads started by Go, letting other goroutines
      displace them sporadically. Whether more or fewer processors are preferable is to be determined
      experimentally.

      The number of kernel threads that go creates depends on the number of usable cores, which is
      controlled by the environment variable ``GOMAXPROCS``. See :envvar:`GOMAXPROCS`.

   .. option:: router.num_slow_processors = <int> (Default: 1)

      Number of goroutines started for the slow-path processing which includes all SCMP traffic and
      traceroutes. A minimum of 1 slow-path processor is required.

   .. option:: router.batch_size = <int> (Default: 256)

      The batch size used by the receiver and forwarder to
      read or write from / to the network socket.

   .. object:: bfd

      .. option:: disable = <bool> (Default: false)

         Set whether the :term:`BFD` feature is disabled by default.

         This setting applies to BFD sessions to all neighboring routers, including sibling routers
         (other routers in the same AS).

         Can be overridden for specific inter-AS BFD
         sessions with :option:`bfd.disable <topology-json disable>`.

      .. option:: detect_mult = <uint8>, default 3

         Set the :term:`BFD` detection time multiplier.

         After ``detect_mult`` consecutively missing control packets, the BFD session is
         considered "down" and is reset.

         Can be overridden for specific inter-AS BFD sessions with
         :option:`bfd.detect_mult <topology-json detect_mult>`.

      .. option:: desired_min_tx_interval = <duration>, default 200ms

         Defines the frequency at which this router should send :term:`BFD` control messages.
         The effective interval is the result of negotiating with the remote router during
         session establishment;
         the value will be ``max(desired_min_tx_interval, remote.required_min_rx_interval)``.

         Can be overridden for specific inter-AS BFD sessions with
         :option:`bfd.desired_min_tx_interval <topology-json desired_min_tx_interval>`.

      .. option:: required_min_rx_interval = <duration>, default 200ms

         Defines an upper bound for the frequency at which this router wants to receive
         :term:`BFD` control messages.
         The effective interval at which the remote router will send control messages is the
         result of negotiating with the remote router during session establishment;
         the value will be ``max(remote.desired_min_tx_interval, required_min_rx_interval)``

         Can be overridden for specific inter-AS BFD sessions with
         :option:`bfd.required_min_rx_interval <topology-json required_min_rx_interval>`.

   .. object:: preferred_underlays

      .. option:: udpip = <string>, default = "afxdp"

         Selects an implementation for the "udpip" underlay protocol. If the preferred
         implementation is not available then any other available implementation is selected.
         As of this writing, two implementations exist for the "udpip" underlay protocol:

         * "inet": An implementation based on AF_INET sockets and portable to many Unix-like
           platforms.
         * "afxdp": An implementation based on AF_XDP sockets and eBPF filtering, which
           is less portable and requires Linux 5.9 or later (for BPF link-based XDP
           attachment). See :ref:`router-afxdp-prerequisites`.

         In the absence of ``preferred_underlays``, "afxdp" is preferred; falling back to
         "inet".

      .. option:: <underlay_protocol> = <string>

         Sets the given string as the preferred implementation for the given underlay protocol.
         The ``preferred_underlays`` section is handled as a map, so any key may be used (to
         designate future underlay protocols). Entries for nonexistent underlay protocols are
         silently ignored.

.. _router-afxdp-prerequisites:

AF_XDP Prerequisites
--------------------

The ``afxdp`` underlay implementation requires:

* **Linux 5.9 or later**: AF_XDP is a Linux-specific API. On non-Linux platforms or older
  kernels, the router automatically falls back to the ``inet`` implementation.

* **Linux capabilities**: The following capabilities must be granted to the router process:

  - ``CAP_NET_ADMIN`` -- required for attaching the XDP program to network interfaces.
  - ``CAP_NET_RAW`` -- required for creating AF_XDP sockets.
  - ``CAP_BPF`` -- required for loading the eBPF program.

  The provided systemd unit file (``scion-router@.service``) already grants these capabilities
  via ``AmbientCapabilities``. On OpenWrt, the init script grants them via ``setcap``.

* **NIC driver support**: Zero-copy mode (``XDP_ZEROCOPY``) requires driver support.
  If the driver does not support zero-copy, the implementation silently falls back to
  copy mode (``XDP_COPY``). Copy mode works with any NIC driver that supports XDP but
  achieves lower performance due to the additional data copy between kernel and userspace.

* **Hugepages** (optional): For best performance, 2 MB hugepages should be available for UMEM
  allocation. The underlay automatically falls back to normal pages if hugepages are unavailable.

If the kernel or capability requirements are not met, the router automatically falls back
to the ``inet`` underlay.

.. _router-afxdp-options:

AF_XDP Per-Link Options
-----------------------

When using the ``afxdp`` underlay, each interface entry in ``topology.json`` can include
an ``options`` field containing a JSON object with AF_XDP tuning parameters. All fields
are optional; defaults are chosen for general-purpose use.

.. code-block:: json
   :caption: Example ``underlay.options`` for AF_XDP tuning.

   {
      "rx_queues": [0, 1, 2, 3],
      "tx_queues": [0, 1],
      "prefer_zerocopy": true,
      "prefer_hugepages": true,
      "num_frames": 4096,
      "frame_size": 2048,
      "rx_size": 2048,
      "tx_size": 2048,
      "cq_size": 2048,
      "batch_size": 64
   }

.. program:: router-afxdp-options

.. option:: rx_queues = [<uint32>, ...]

   Explicit list of NIC queue IDs to use for receiving packets. Each listed
   queue gets an AF_XDP socket with a receiver goroutine, and incoming packets
   on that queue are dispatched to the appropriate link.

   Can be combined with ``tx_queues`` to configure RX and TX independently
   (e.g. when a NIC has more RX queues than TX queues).

   If omitted, RX queues are auto-detected from
   ``/sys/class/net/<interface>/queues/rx-*``.

.. option:: tx_queues = [<uint32>, ...]

   Explicit list of NIC queue IDs to use for sending packets. Outgoing packets
   are distributed across these queues via a flow hash to prevent reordering.

   Can be combined with ``rx_queues`` to configure RX and TX independently.

   If omitted, TX queues are auto-detected from
   ``/sys/class/net/<interface>/queues/tx-*``.

.. option:: prefer_zerocopy = <bool> (Default: true)

   Prefer ``XDP_ZEROCOPY`` mode, which avoids copying packet data between
   kernel and userspace. Falls back to ``XDP_COPY`` if the NIC driver does
   not support zero-copy.

   Setting this to ``false`` forces copy mode, which is only useful for
   debugging or benchmarking.

.. option:: prefer_hugepages = <bool> (Default: true)

   Prefer 2 MB hugepages for UMEM allocation. Falls back to normal pages if
   hugepages are not available.

.. option:: num_frames = <uint32> (Default: 4096)

   Total number of UMEM frames. Must be a power of two and at least
   ``rx_size + tx_size``.

   Each frame holds one packet. The total UMEM memory
   consumed per queue is ``num_frames * frame_size`` bytes. Increasing this
   value allows more packets to be in-flight simultaneously, which helps
   absorb traffic bursts at the cost of higher memory usage.

.. option:: frame_size = <uint32> (Default: 2048)

   Size of each UMEM frame in bytes. Must be a power of two, at least 2048,
   and at most the system page size (typically 4096).

   Each frame must be large enough to hold a full SCION packet including the
   underlay (Ethernet, IP, and UDP) headers. The default of 2048 is sufficient for
   standard MTU traffic.

.. option:: rx_size = <uint32> (Default: 2048)

   Number of descriptors in the RX ring. Must be a power of two.

   A larger ring absorbs incoming traffic bursts without dropping packets when the
   application is temporarily slow to consume them. Requires more UMEM frames
   to be available (see ``num_frames``).

.. option:: tx_size = <uint32> (Default: 2048)

   Number of descriptors in the TX ring. Must be a power of two.

   A larger ring allows more outgoing packets to be queued before the NIC completes
   transmission, reducing backpressure to the packet processors under
   bursty forwarding loads. Requires more UMEM frames to be available (see
   ``num_frames``).

.. option:: cq_size = <uint32> (Default: 2048)

   Number of descriptors in the completion ring. Must be a power of two.

   The completion ring returns transmitted frame addresses back to userspace.
   A larger ring prevents TX stalls when the NIC takes longer to complete
   transmissions, at the cost of additional kernel memory. Should generally
   match ``tx_size``.

.. option:: batch_size = <uint32> (Default: 64)

   Number of packets batched per TX submission. Must be non-zero.
   Values above 256 are capped to 256.

   Larger batches amortize per-syscall overhead but increase per-packet latency.
   Values that are too large can cause latency spikes, especially in copy mode.

.. _router-conf-topo:

topology.json
-------------

The :program:`router` reads the ``border_routers`` section of the :ref:`topology.json <common-conf-topo>` file.

It uses the entry referring to its own :option:`general.id <router-conf-toml general.id>`
to determine the intra-AS links that this router instance is responsible for.
The other router entries ("sibling routers") define which router is responsible for which
interface. This mapping is consulted during packet forwarding to determine the
sibling router to which a packet transiting the AS needs to forwarded to.

Additionally, the :program:`router` considers the ``control_service`` and ``discovery_service``
entries. These entries define the underlay addresses that the router uses to resolves
anycast or multicast service addresses.

.. _router-conf-keys:

Keys
----

The :program:`router` loads the forwarding secret keys ``master0.key``/``master1.key`` from :option:`<config_dir>/keys <router-conf-toml general.config_dir>`.

The key files contain a base64-encoded high-entropy random string.
The keys should be exactly 16 bytes long (corresponding to a base64 encoding of 24 bytes with two trailing pad bytes ``==``).
These keys must be identical to the :ref:`corresponding keys used by the control service <control-conf-keys>`.

.. note::
   The :program:`router` and :doc:`control` currently use these keys as input for PBKDF2 to generate
   the actual forwarding key. Consequently, keys of any size can currently be used. This may be changed
   to only accept high-entropy 16 byte keys directly in the future.

Port table
==========

.. include:: ./router/port-table.rst

Metrics
=======

.. include:: ./router/metrics.rst

HTTP API
========

.. include:: ./router/http-api.rst
