***************
Control Service
***************

:program:`control` is the SCION control service.
It discovers SCION paths by participating in the inter-domain path-dissemination process called
"beaconing".
It signs and validates the path information based on the :term:`Control-Plane PKI <CP-PKI>`.

The :program:`control` service is also the recursive resolver for path information for endpoints in
the local AS.

In ASes with the :ref:`CA role<overview-as-roles>`, the :program:`control` service also acts as the
certificate authority from which ASes in the local ISD request renewed certificates (or as a proxy
thereof).

See :doc:`/control-plane` for an introduction to the SCION control plane and the tasks of the
:program:`control` service.

Command line reference
======================

.. program:: control

Synopsis
--------

:program:`control` [:option:`--config \<config.toml\> <control --config>` | :option:`help <control help>` | :option:`version <control version>`]


Options
-------

.. option:: --config <config.toml>

   Specifes the :ref:`configuration file <control-conf-toml>` and starts the control service.

.. option:: help, -h, --help [subcommand]

   Display help text for subcommand.

.. option:: version

   Display version information.

.. option:: sample [file]

   Display sample files.

   .. option:: config

      Display a sample :ref:`configuration file <control-conf-toml>`.

   .. option:: policy

      Display a sample :ref:`beaconing policy file <control-conf-beacon-policies>`

.. option:: completion [shell]

   Generate the autocompletion script for :program:`control` for the specified shell.

   Run :option:`control help completion <control help>` for a list of the available shells.

   Run :option:`control help completion [shell] <control help>` for usage information on the
   autocomplete script for a particular shell.

.. _control-envvars:

Environment variables
---------------------

.. envvar:: SCION_TESTING_DRKEY_EPOCH_DURATION

   For **testing only**.

   Override the global duration for :doc:`/cryptography/drkey` epochs.
   This can only work correctly if the same value is set for all connected control services in the
   test network.

   Also applies to the :ref:`router <router-envvars>`.

   :Type: :ref:`duration <common-conf-duration>`
   :Default: ``24h``

Configuration
=============

The :program:`control` service is configured with multiple files:

- the :ref:`.toml <control-conf-toml>` file,
  specified on the command line by the :option:`--config <control --config>` option, is the main
  configuration file.
  It configures common features like logging and metrics and
  specifies the **configuration directory** from which all other configuration files are read.
- :ref:`topology.json <control-conf-topo>`, contains information about the inter-AS links
- :ref:`beaconing policy <control-conf-beacon-policies>` configuration files
- :ref:`crypto/ and certs/ <control-conf-cppki>` contain :term:`CP-PKI` certificates and private keys
- :ref:`keys/ <control-conf-keys>` contains the AS's forwarding secret keys
- :ref:`staticInfoConfig.json <control-conf-path-metadata>`, if it exists, specifies values for the :doc:`/beacon-metadata`.

.. _control-conf-toml:

Control service configuration
-----------------------------

In addition to the :ref:`common .toml configuration options <common-conf-toml>`, the control service
considers the following options.

.. program:: control-conf-toml

.. object:: general

   .. option:: general.id = <string> (Required)

      An identifier for this control service.

      This is used to identify which parts of the :ref:`control-conf-topo` file are refering to self.
      Thus, ``id`` must match a key in the :ref:`control-conf-topo` files' ``control_service`` section.

   .. option:: general.config_dir = <string> (Required)

      Path to a directory containing the remaining configuration files.

      If this is a relative path, it is interpreted as relative to the current working directory of the
      program (i.e. **not** relative to the location of this .toml configuration file).

   .. option:: general.reconnect_to_dispatcher = <bool> (Default: false)

      Transparently reconnect to the dispatcher on dispatcher failure or restarts.

      .. Warning::
         This should be set to ``true``, unless your service orchestration ensures that
         failures of the dispatcher also trigger a restart of :program:`control`.

.. object:: features

   Features is a container for generic, boolean feature flags (usually for experimental or
   transitional features).

   .. option:: features.appropriate_digest_algorithm = <bool> (Default: false)

      Enables the CA module to sign issued certificates
      with the appropriate digest algorithm instead of always using ECDSAWithSHA512.

      **Transition**: This behaviour should be enabled unless there is a specific requirement to
      interface with older versions of SCION that don't support these certificates.
      The default for this flag will be changed to ``true`` in future releases, and the flag will
      eventually be removed.

.. object:: api

   .. option:: api.addr = <string> (Optional)

      Address at which to expose the :ref:`control-rest-api`,
      in the form ``host:port``, ``ip:port`` or ``:port``.

.. object:: tracing

   Tracing with `OpenTracing <https://opentracing.io/>`_ / `Jaeger <https://www.jaegertracing.io/>`_.
   This is especially helpful when collecting the traces of multiple service instances, e.g. when
   :doc:`running a local SCION topology </dev/run>`.

   .. option:: tracing.enabled = <bool> (Default = false)

   .. option:: tracing.debug = <bool> (Default = false)

   .. option:: tracing.agent = <string> (Default = "localhost:6831")

      Address of the local agent that handles the reported traces.

.. object:: quic

   .. option:: quic.address = <ip:port> (Optional)

      Local SCION address for inter-AS communication by QUIC/gRPC.
      By default, the address used is that specified for this control service in its ``control_service`` entry of
      the :ref:`control-conf-topo`.

.. object:: beaconing

   .. option:: beaconing.origination_interval = <duration> (Default = "5s")

      Specifies the interval between originating beacons in a core AS.

   .. option:: beaconing.propagation_interval = <duration> (Default = "5s")

      Specifies the interval between propagating beacons.

   .. option:: beaconing.registration_interval = <duration> (Default = "5s")

      Specifies the interval between registering path segments.

   .. option:: beaconing.policies

      File paths for :ref:`control-conf-beacon-policies`.
      If these are the empty string, the default policy is used.

      The different policies *may* point to the same file(s).

      .. option:: beaconing.policies.propagation = <string>
      .. option:: beaconing.policies.core_registration = <string>
      .. option:: beaconing.policies.up_registration = <string>
      .. option:: beaconing.policies.down_registration = <string>


   .. option:: beaconing.epic = <bool> (Default: false)

      Specifies whether the EPIC authenticators should be added to the beacons.

.. object:: path

   .. option:: path.query_interval = <duration> (Default = "5m")

      Specifies after how much time path segments for a destination AS should be refetched.

   .. option:: path.hidden_paths_cfg = <string> (Optional)

      Location of the :doc:`hidden paths </hidden-paths>` configuration.

      The location is specified as a file path (relative to the working directory of the program)
      or an HTTP/HTTPS URL.

.. object:: ca

   .. option:: ca.mode = "disabled"|"in-process"|"delegating" (Default: "disabled")

      Mode defines whether the :program:`control` should handle certificate issuance requests.
      This should be enabled in core ASes that are labeled as ``issuing`` ASes in the :term:`TRC`.

      If set to ``in-process``, :program:`control` handles certificate issuance requests on its own.
      If set to ``delegating``, the certificate issuance is delegated to the service defined in
      :option:`ca.service <control-conf-toml ca.service>`.

   .. option:: ca.max_as_validity = <duration> (Default: "3d")

         Defines the the maximum lifetime for renewed AS certificates.

   .. option:: ca.service

      Configuration for the :term:`CA` service,
      effective with the :option:`ca.mode <control-conf-toml ca.mode>` mode ``delegating``.

      The CA service is expected to implement the API described by :file-ref:`spec/ca.gen.yml`.

      .. Hint::
         The `scionproto/scion <https://github.com/scionproto/scion>`_ project does not include such
         a standalone CA service implementation.

         The available options are:

         - use the built-in CA implementation (using :option:`ca.mode = "in-process" <control-conf-toml ca.mode>`),
         - use the `netsys-lab/scion-ca <https://github.com/netsys-lab/scion-ca>`_ SCION CA
           based on `smallstep's step-ca <https://github.com/smallstep/certificates>`_,
         - ask SCION vendors for proprietary CA implementations and offerings,
         - plug in your own CA service implementing the :file-ref:`spec/ca.gen.yml` API.

      .. option:: ca.service.address = <string>

         Address of the CA Service that handles the delegated certificate renewal requests.
         Specified with scheme, for example ``https://ca-service.local``, and optional
         path relative to the server, such as ``https://ca-service.local/dev-test``.

      .. option:: ca.service.shared_secret = <string>

         Path to the PEM-encoded shared secret that is used to create JWT tokens.

         The shared secret file is re-read from disk at 5 second intervals.

      .. option:: ca.service.lifetime = <duration> (Default: "10m")

         Validity period (a :ref:`duration <common-conf-duration>`) of JWT authorization tokens
         for the CA service.

      .. option:: ca.service.client_id = <string> (Default: general.id)

         Client identifier for the CA service.
         Defaults to :option:`general.id <control-conf-toml general.id>`.

.. option:: beacon_db (Required)

   :ref:`Database connection configuration <common-conf-toml-db>`
   for received :term:`PCB`\s.

   This database holds beacons that may be candidates for propagation.
   If it is destroyed, the control service may temporarily not have beacons to propagate to
   downstream neighbor ASes, until fresh PCBs are received from upstream neighbor ASes.

.. option:: trust_db (Required)

   :ref:`Database connection configuration <common-conf-toml-db>`
   for :term:`Control-Plane PKI` information.

   This database file contains cached TRC and AS certificate chains.
   If it is destroyed, the control service will load locally available TRCs and certificate chains
   from the corresponding :ref:`configuration directory <control-conf-cppki>`, and fetch other
   certificate information from authoritative ASes on-demand.

.. option:: path_db (Required)

   :ref:`Database connection configuration <common-conf-toml-db>`
   for Path Segment data.

   This database contains path segments, both explicitly registered segments resulting from the
   beaconing process, as well as cached results from path segment queries.
   If it is destroyed, the explicitly registered paths may be lost until
   they are rediscovered by the beaconing process. The path segments from cached path segment
   queries will be re-fetched on-demand.

.. object:: trustengine.cache

   Control the **experimental** in-memory caching of ISD/AS attribute information extracted from
   :term:`TRCs <TRC>`.

   .. option:: trustengine.cache.disable = <bool> (Default: false)

      Disable caching entirely.

   .. option:: trustengine.cache.expiration = <duration> (Default: "1m")

      Expiration time for cached entries.

.. object:: drkey

   Configuration for the optional and still somewhat **experimental** :doc:`Dynamically Recreatable Key (DRKey) infrastructure </cryptography/drkey>`.

   See also :envvar:`SCION_TESTING_DRKEY_EPOCH_DURATION`.

   .. option:: drkey.level1_db (Optional)

      Enables the DRKey infrastructure if set.

      :ref:`Database connection configuration <common-conf-toml-db>`
      for cached :ref:`AS-AS (Level 1) keys <drkey-as-as>`.

      If it is destroyed, the control service may need to re-fetch keys from remote ASes.

   .. option:: drkey.secret_value_db

      Required if :option:`drkey.level1_db <control-conf-toml drkey.level1_db>` is set.

      :ref:`Database connection configuration <common-conf-toml-db>`
      for key epochs and the corresponding :ref:`secret values (Level 0 keys) <drkey-secret>`
      derived from the :ref:`AS master keys <control-conf-keys>`.

      .. warning::

         This database is not a cache.

         If it is destroyed, the control service loses track of previously created key epochs.
         As key derivation depends on the epoch, keys that have previously been requested / derived,
         will not match any newly created keys.
         The DRKey system is broken for this AS, at least until all entities have fetched new keys,
         which may only happen after multiple epochs.

   .. option:: drkey.delegation = <map[protocol-id]: list[ip-address]> (Optional)

      Defines hosts with privileged access to obtain the protocol and epoch specific
      :ref:`secret value (Level 0 key) <drkey-secret>`.
      These hosts can locally derive keys shared with any remote AS, without having to request
      them individually from the control service.
      However, the hosts must be trusted to not abuse this, as they can also create keys
      to impersonate any other host in the AS.

      The set of hosts authorized to access the secret value for delegated key derivation
      are specified as a list of IP addresses per supported :ref:`DRKey protocol identifier <drkey-protocol-identifiers>`.

      .. code-block:: toml

         # Example

         [drkey.delegation]
         scmp = ["203.0.113.17", "198.51.100.249"]

   .. option:: drkey.prefetch_entries = <number> (Default: 10000)

      Maximum number of Level 1 keys that will be re-fetched preemptively before their expiration.

.. _control-conf-topo:

topology.json
-------------

The :program:`control` service reads the ``control_service`` section of the :ref:`topology.json <common-conf-topo>` file.

The entry referring to its own :option:`general.id <control-conf-toml general.id>`
define the addresses that :program:`control` will listen on.

The interface definitions in the ``border_router`` entries define the inter-AS links.
These entries define the beacons that :program:`control` will originate and propagate.

.. _control-conf-beacon-policies:

Beaconing policies
------------------

A beaconing policy is a YAML file, defining processing rules for path-segment construction and
registration.
There are four policies with different but related purposes, that can individually be configured
with the :option:`beacon.policies <control-conf-toml beaconing.policies>` options:

Propagation
   Propagation is the process of receiving a beacon from a neighbor AS, extending it
   with one's own AS entry and forwarding it to downstream neighbor ASes.
   See :ref:`control-plane-beaconing`.

   The propagation policy determines which beacons are selected to be propagated and how they are
   extended.

   Note that there is no separate policy type for beacon origination. The only policy value
   affecting origination is the :option:`MaxExpTime <control-conf-beacon-policy MaxExpTime>`, which is
   read from the propagation policy.

Registration
   Registration is the process of making beacons available as path-segments to the path lookup
   process.
   Beacons received from a neighbor AS are "terminated" by appending the own AS entry and registered
   in a path-segment database, from which it can be later found with path-segment queries.
   See :ref:`control-plane-registration`.

   CoreRegistration
      Applies to the registration of core-segments in the local path store of a core AS.

   UpRegistration
      Applies to the registration of up-segments in the local path store of a non-core AS.

   DownRegistration
      Applies to the registration of down-segments. The policy is used by a non-core AS
      to determine which down-segments it wants to make available to other ASes.
      Each selected down-segments is registered, via a segment registration request, in the core AS
      that originated it.

      .. note::
         There is currently no corresponding policy that applies to the processing of segment
         registration requests in the core AS.

From the description above, it is already evident that not all four policies are applicable for
core and non-core ASes. Summarizing this:

.. table::

   ================= ================================================
   AS type           Applicable policies
   ================= ================================================
   core              Propagation, CoreRegistration
   non-core          Propagation, UpRegistration, DownRegistration
   ================= ================================================


The beaconing policy YAML configuration considers the following options:

.. program:: control-conf-beacon-policy

.. option:: Type = "Propagation"|"UpSegmentRegistration"|"DownSegmentRegistration"|"CoreSegmentRegistration" (Default: "")

   Restrict this policy configuration file to be used exclusively as one of the
   :option:`beacon.policies <control-conf-toml beaconing.policies>` options.

   Only as sanity check and organization of configuration files. No operational effect.

.. option:: BestSetSize = int (Default: 20)

   Maximum number of segments to propagate/register **per origin AS**.

   In the ``Propagation`` policy, this parameter determines the number of beacons
   propagated to neighbor ASes per origin AS.
   That is, for each originating AS, up to ``BestSetSize`` beacons are forwarded.
   For the core-beaconing process, the set of originating ASes are all other core ASes, which can
   be very numerous.

   .. warning::

      Keep this parameter reasonably low to avoid an explosion of beacon numbers.

.. option:: CandidateSetSize = int (Default: 100)

   Maximum number of segments to keep in beacon store and consider for selection to best set **per
   origin AS**.

.. option:: MaxExpTime = uint8 (Default: 63)

   Defines the maximum relative expiration time for the AS Entry when originating, propagating or
   terminating a PCB.

   .. note::
      For beacon origination, the ``MaxExpTime`` value from the ``Propagation`` policy is used.

   The 8 bit unsigned integer :ref:`ExpTime <scion-path-exptime>` fields represents an expiration
   relative to the origination timestamp of the segment, with a nonzero minimum and a maximum
   of 24 hours:

   .. math::
        (1 + ExpTime) \cdot \frac{24\cdot60\cdot60}{256}\mathrm{s}

   Every increment of `ExpTime` represents 5 minute and 37.5 seconds in duration.

   ============= ================
   ``ExpTime``   Duration (h:m:s)
   ============= ================
   0             0:05:37.5
   1             0:11:15
   2             0:16:52.5
   ...           ...
   9             0:56:15
   10            1:01:52.5
   11            1:07:30
   ...           ...
   63            6:00:00
   ...           ...
   254           23:54:22.5
   255           24:00:00
   ============= ================

.. option:: Filter

   Filters restrict the allowed beacons for the purposes of the policy (i.e. for propagation or
   the different forms of registration).

   Filters are applied when a beacon is received, resulting in a "usage" classification of the
   beacon that is stored in the local beacon database.
   Therefore, when the policy is changed, it will only be effective for newly received beacons.

   .. note::

      Filters are currently not very expressive. Specifically, they cannot express filtering rules
      that take into account the ingress or egress interface of the beacon.

      There are plans to extend this functionality but so far there are no concrete proposals.
      If you're interested in working on this, get in contact in the :ref:`chat <slack>` or create a
      :ref:`proposal <change-proposal-process>` on github.

   .. option:: MaxHopsLength = <int>

      Upper bound for the allowed number of AS entries in a received PCB.

      Filters are applied for received PCBs, before extending the segment.
      Consequently, a propagated/terminated PCB may have up to ``MaxHopsLength + 1`` AS entries.

   .. option:: AsBlackList = <List[AS identifier]>

      Deny-list for ASes.
      PCBs with any AS entry from any of the specified AS identifiers will be rejected.

   .. option:: IsdBlackList = <List[ISD identifier]>

      Deny-list for ISDs.
      PCBs with any AS entry from any of the specified ISD identifiers will be rejected.

   .. option:: AllowIsdLoop = <bool> (Default: true)

      Specifies whether ISD loops are allowed.

      A PCB is considered to be an ISD loop if it leaves and then re-enters an ISD.

.. _control-conf-cppki:

Control-Plane PKI
-----------------

TRCs
   :option:`<config_dir>/certs <control-conf-toml general.config_dir>`

   The :term:`TRC`\s for the :term:`Control-Plane PKI` are loaded from here.
   TRCs are also written back to the :option:`trust_db <control-conf-toml trust_db>`.

   Any TRC loaded from this directory will be written back to the trust_db.
   Updated TRCs fetched from authoritative core ASes are stored both here in the filesystem and
   in the trust_db.

   :program:`control` scans this directory for new TRCs at startup, and also when requesting signing
   keys and the corresponding certificate chains.

   .. note::
      :program:`control` does **not** create TRCs.
      TRC creation is an offline process, the :doc:`/cryptography/trc-signing-ceremony`.

      However, the :program:`control` does fetch new TRCs from neighbor ASes and store them into
      this directory (<config_dir>/certs).


AS Certificates and Keys
   :option:`<config_dir>/crypto/as <control-conf-toml general.config_dir>`

   :ref:`AS certificate chains <cp-as-certificate>` and the corresponding keys,
   used for signing control-plane messages and authenticating TLS sessions to other control
   services, are loaded from here.
   Certificates are also written back to the :option:`trust_db <control-conf-toml trust_db>` (but
   keys are not).

   :program:`control` scans this directory for new certificates at startup, and also when loading
   keys on demand.

   Keys are loaded from this directory on demand, with an in-memory cache with a lifetime of 5
   seconds.

   .. note::
      :program:`control` does **not** request renewal of its AS certificates.

      Certificate renewal can be requested using the :ref:`scion-pki_certificate_renew` tool.
      Because AS certificates have short lifetimes, this *should* be automated by the operator.

CA Certificates and Keys
   :option:`<config_dir>/crypto/ca <control-conf-toml general.config_dir>`

   If the in-process :term:`CA` is used, :option:`ca.mode = "in-process" <control-conf-toml ca.mode>`,
   the :ref:`CA certificates <cp-ca-certificate>` and corresponding keys are read from this
   directory on demand, whenever a certificate renewal request is handled.

   .. note::
      Even if it is operating with active CA mode,
      :program:`control` does **not** issue initial certificates for new ASes.
      Issuance of initial AS certificates is an offline process. See :ref:`ca-ops-as-certs`.

The control service is not directly involved in the creation of TRCs and consequently it is not
concerned with voting certificates.

.. _control-conf-keys:

Keys
----

:program:`control` loads the forwarding secret keys ``master0.key``/``master1.key`` from :option:`<config_dir>/keys <control-conf-toml general.config_dir>`.

The key files contain a base64-encoded high-entropy random string.
The keys should be exactly 16 bytes long (corresponding to a base64 encoding of 24 bytes with two trailing pad bytes ``==``).
These keys must be identical to the :ref:`corresponding keys used by the routers <router-conf-keys>`.

.. note::
   The :program:`router` and :doc:`control` currently use these keys as input for PBKDF2 to generate
   the actual forwarding key. Consequently, keys of any size can currently be used. This may be changed
   to only accept high-entropy 16 byte keys directly in the future.

.. _control-conf-path-metadata:

Path Metadata
-------------

The ``StaticInfoExtension`` PCB extension allows to announce :doc:`path metadata in beacons </beacon-metadata>`.

:program:`control` loads the information for the ``StaticInfoExtension``
for its AS entries from the optional JSON configuration file
:option:`<config_dir>/staticInfoConfig.json <control-conf-toml general.config_dir>` if it exists.

This configuration is **optional**.
If the file does not exist, or if the configuration does not specify values for certain metadata
types or for certain interfaces, the corresponding ``StaticInfoExtension`` will either be omitted or
include only partial metadata.

If the configuration file exists, it must be syntactically valid.

The structure of the configuration is presented as pseudo-JSON with a more detailed explanation
of the individual fields below.

.. code-block:: yaml
   :caption: Pseudo-JSON description of the structure of the ``staticInfoConfig.json`` configuration file.
   :name: staticinfoconfig-json-structure

   {
      "Latency": {
         <interface-id>: {
            "Inter": <duration>,
            "Intra": {
               <interface-id>: <duration>
               # ...
            }
         }
         # ...
      },
      "Bandwidth": {
         <interface-id>: {
            "Inter": <number>,
            "Intra": {
               <interface-id>: <number>
               # ...
            }
         }
         # ...
      },
      "Geo": {
         <interface-id>: {
            "Latitude": <number>,
            "Longitude": <number>,
            "Address": <string>
         }
         # ...
      },
      "Linktype": {
         <interface-id>: <"direct"|"multihop"|"opennet">
         # ...
      },
      "Hops": {
         <interface-id>: {
            "Intra": {
               <inteface-id>: <number>
               # ...
            }
         }
         # ...
      },
      "Note": <string>
   }

.. seealso::

   :ref:`Example staticInfoConfig.json <path-metadata-example-conf>` in the
   :doc:`/beacon-metadata` section.


There is one top-level entry for each type of metadata, all of which are optional.
:term:`Interface ID` keys must be specified as strings (not numbers), e.g. ``"5"``.

.. program:: control-conf-metadata

.. option:: Latency

   Object where the keys are Interface ID ``i`` and the values are objects with:

   .. option:: Inter = <duration>

      Latency from interface ``i`` to the associated remote AS border router.

   .. option:: Intra = <map[interface-id j]: duration>

      Latency from interface ``i`` to interface ``j``.

.. option:: Bandwidth

   Object where the keys are Interface ID ``i`` and the values are objects with:

   .. option:: Inter = <number>

      Bandwidth in Kbit/s between interface ``i`` and the associated remote AS border router.

   .. option:: Intra = <map[interface-id j]: duration>

      Bandwidth in Kbit/s between interface ``i`` to interface ``j``.

.. option:: Geo

   Object where the keys are Interface ID ``i`` and the values are objects with:

   .. option:: Latitude = <number

      Longitude GPS coordinates of interface ``i``.

   .. option:: Longitude = <number>

      Latitude GPS coordinate of interface ``i``.

   .. option:: address = <string>

      Free-form civic address of interface ``i``.

.. option:: LinkType

   Object where the keys are Interface ID ``i`` and the values describe the link associated
   with interface ``i`` as one of:

   ``"direct"``
      Direct physical connection.

   ``"multihop"``
      Connection with local routing/switching.

   ``"opennet"``
      Connection overlayed over publicly routed Internet.

.. option:: Hops

   Object where the keys are Interface ID ``i`` and the values are objects with:

   .. option:: Intra = map[interface-id j]: number

      Number of internal hops (e.g. number of AS-internal IP routers) between interface ``i`` and
      interface ``j``.

.. option:: Note = <string>

   A free form string to communicate interesting/important information to other network operators.

Port table
==========

.. include:: ./control/port-table.rst

Metrics
=======

.. include:: ./control/metrics.rst

.. _control-http-api:

HTTP API
========

.. include:: ./control/http-api.rst

.. _control-rest-api:

REST API
========

The REST API described by the OpenAPI specification :file-ref:`spec/control.gen.yml`
is exposed by :program:`control` on the address defined by
:option:`api.addr <control-conf-toml api.addr>`.

Note that this is **separate** from the partially redundant, ad hoc :ref:`control-http-api`.

Specification
-------------

.. openapi:: /../spec/control.gen.yml
   :group:
