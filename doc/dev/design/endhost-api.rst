*******************
SCION Endhost API
*******************

- Author(s): Samuel Hitz (main), Jordi Subirà-Nieto
- Last updated: 2026-11-19
- Discussion at: :issue:`4834`
- Status: **WIP**

Abstract
--------

This document proposes a new SCION Endhost API that replaces the current SCION
daemon gRPC API. The new API provides underlay discovery for multiple transport
types, segment-based path retrieval with pagination, cryptographic material for
client-side path verification, and optional DRKey key retrieval. It uses
`ConnectRPC <https://connectrpc.com/>`_ over HTTP with mandatory TLS server authentication
on network transports.

Background
----------

The current SCION daemon exposes a ``DaemonService`` gRPC API
(``proto/daemon/v1/daemon.proto``) with 9 RPCs:

- ``Paths`` -- return pre-built end-to-end paths to a destination.
- ``AS`` -- return information about an AS (ISD-AS, core flag, MTU).
- ``Interfaces`` -- return underlay addresses for local interfaces.
- ``Services`` -- return addresses for local infrastructure services.
- ``NotifyInterfaceDown`` -- notify the daemon of a failing interface.
- ``PortRange`` -- return the dispatched port range for the local AS.
- ``DRKeyASHost``, ``DRKeyHostAS``, ``DRKeyHostHost`` -- DRKey retrieval.

This API was designed around a co-located daemon process that caches path
segments and serves pre-computed end-to-end paths. Several limitations motivate
a redesign:

1. **Multiple underlays.** The current API assumes a single UDP/IP underlay.
   Future deployments may use additional transport underlays (e.g.,
   SNAP underlay). The API must support discovering and selecting among
   multiple underlay types.

2. **Path API limitations.** Returning pre-built end-to-end paths prevents
   clients from verifying path segments against the CP-PKI, limits flexibility
   in path construction, and makes it difficult to compose paths with segments
   obtained from other sources (e.g., hidden path servers).

3. **Daemon-less operation.** The requirement for a co-located daemon process
   is a significant barrier on platforms where running a shared background
   service is impractical (e.g., mobile platforms).
   PRs :issue:`4868`, :issue:`4869`, :issue:`4870` and :issue:`4871` already allow for
   self-contained applications that do not require a local daemon, but the API design still
   inherits the limitations of the original daemon-centric model.

4. **Client authentication.** Certain operations (e.g., DRKey retrieval)
   benefit from authenticated requests. Thus the API should support client authentication.

Related design documents:

- :doc:`router-port-dispatch` -- dispatching based on UDP/SCION ports.
- :doc:`endhost-bootstrap` -- automated end host bootstrapping.

Proposal
--------

This section specifies the SCION Endhost API. The API is defined in proto3
and served over ConnectRPC.

Specification Format and Protocol
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The API is specified in Protocol Buffers version 3 (proto3). It is served using
`ConnectRPC <https://connectrpc.com/>`_ over HTTP.

- **HTTP/1.1** support is required.
- **HTTP/2** and **HTTP/3** support is optional. Servers and clients may use
  ALPN to negotiate the HTTP version.
- All RPCs are **unary** (request-response).
- The content type is ``application/proto``.

Authentication
^^^^^^^^^^^^^^

- **Server authentication** via TLS is mandatory on network transports. The
  server certificate may be issued by a WebPKI CA or a private TLS PKI operated
  by the AS. The server may also use its AS certificate of the SCION CP-PKI.
- If the server uses its AS certificate, the client verifies the certificate
  chain against the TRC of the ISD. The client must have this TRC before it
  connects, for example from the bootstrap process (see
  :doc:`endhost-bootstrap`). The client must not take the trust anchor for this
  verification from the same server. The AS certificate identifies an ISD-AS,
  not a host name. Thus the client also checks that the ISD-AS in the
  certificate is the local AS that it expects.
- On a local transport, for example a Unix domain socket, TLS is not required.
  The file system permissions of the socket authenticate the server.
- **Client authentication** is optional. Any HTTP-based authentication scheme
  (e.g., mTLS, bearer tokens) may be used. Client authentication is, for
  instance, relevant for DRKey retrieval, where the server must authorize
  certain requests.

Endhost API Discovery
^^^^^^^^^^^^^^^^^^^^^

The mechanism for discovering the endhost API endpoint is out of scope for this
document. The minimum bootstrap information required is the **endhost API URL**
(scheme, host, port, and path prefix).

See :doc:`endhost-bootstrap` for the general bootstrapping framework. How the
endhost API URL is integrated into the bootstrap process is left for a
dedicated design.

API Versioning
^^^^^^^^^^^^^^

The endhost API uses two version identifiers:

- The **API version** (``Endhost-API-Version``) identifies a version of this
  specification. It does not depend on the vendor of the server. Clients use
  it to find the features that a server supports.
- The **server implementation version** (``Endhost-API-Server-Version``)
  identifies the software of one vendor. It is only for diagnostics.

See also :issue:`4832`.

API Version
"""""""""""

The API version has the format ``<major>.<minor>``:

- The **major version** is the version in the proto package name. For example,
  the package ``scion.endhost.v1`` has the major version 1. The RPC path of each
  request contains the package name, and thus the major version.
- The **minor version** starts at 0 for each major version. The specification
  increments it for each additive change, for example a new field, a new RPC,
  or a new mandatory service. Each additive change in this specification
  states the minor version that adds it. This document specifies version 1.0.

The server MUST report the API version in the HTTP response header
``Endhost-API-Version`` of each response. The major version in the header is
the major version of the request path. The minor version is the highest minor
version whose mandatory parts the server implements completely. The value
MUST match the following regular expression:

``(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)``

If the header is absent, the client assumes the minor version 0.

The minor version solves a problem that protobuf compatibility does not solve.
A server ignores a request field that it does not know, and it does not report
an error. Without the minor version, a client cannot know if the server used
a new request field, for example a filter. A client MUST NOT depend on a
request field that the reported minor version does not contain.

The header costs no additional round trip. A client usually calls
``ListUnderlays`` first, and thus it gets the API version with its first
response.

Breaking Changes
""""""""""""""""

A breaking change, for example the removal of a field or an RPC, requires a new
major version and thus a new proto package, for example ``scion.endhost.v2``.
Because the RPC path contains the package name, a server can serve more than
one major version at the same time.

A client sends its first request with the highest major version that it
supports. If the server returns ``unimplemented``, the client uses the next
lower major version. The client can keep the result for each server.

A removal always requires a new major version. Thus the API does not need a
minimum version.

Optional Services
"""""""""""""""""

The ``TrustService`` and the DRKey service are optional. The API version does
not tell if a server implements an optional service. A server that does not
implement an optional service returns ``unimplemented``. A client that needs an
optional service must handle this case. The client can keep the result for each
server.

Server Implementation Version
"""""""""""""""""""""""""""""

A server SHOULD report its implementation version in the HTTP response header
``Endhost-API-Server-Version``. The value contains a string that identifies
the vendor, and the SemVer version of the server software:

``<vendor>-<major>.<minor>.<patch>``

The value MUST match the following regular expression:

``[a-zA-Z][a-zA-Z0-9]{0,254}-(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)``

Clients MUST NOT use the implementation version to select features. Clients
use the API version for this. The implementation version is for logs and bug
reports.

Examples
""""""""

- RPC path: ``/scion.endhost.v1.UnderlayService/ListUnderlays``

  Response headers: ``Endhost-API-Version: 1.2`` and
  ``Endhost-API-Server-Version: xyz-3.4.1``

  The server implements version 1.2 of the API specification. The server
  software is version 3.4.1 of the vendor ``xyz``.

- RPC path: ``/scion.endhost.v2.UnderlayService/ListUnderlays``

  Response headers: ``Endhost-API-Version: 2.0`` and
  ``Endhost-API-Server-Version: abc-0.3.1``

  The server implements version 2.0 of the API specification. The server
  software is version 0.3.1 of the vendor ``abc``.

- RPC path: ``/scion.endhost.v2.UnderlayService/ListUnderlays``

  Response: ``unimplemented``

  The server does not support the major version 2. The client sends the
  request again with the path ``/scion.endhost.v1.UnderlayService/ListUnderlays``.

Error Handling
^^^^^^^^^^^^^^

The server reports errors with the
`ConnectRPC error codes <https://connectrpc.com/docs/protocol#error-codes>`_. The
response body is a ConnectRPC error. A request that is valid, but that has no
match, is not an error: the server returns an empty response.

.. list-table::
   :header-rows: 1

   * - Condition
     - Response
   * - The request is malformed, for example a wildcard ISD-AS where the RPC
       does not allow it.
     - ``invalid_argument``
   * - The server does not serve the source AS of a ``ListSegments`` request.
     - ``invalid_argument``
   * - The page token is not valid or is expired.
     - ``invalid_argument``. The client starts again at the first page.
   * - The request is valid, but nothing matches, for example an unknown
       destination AS.
     - OK, with an empty response.
   * - The server cannot get the data from its backend, for example from the
       control service.
     - ``unavailable``. The client can retry the request.
   * - The client authentication fails.
     - ``unauthenticated``
   * - The client is not authorized for the request.
     - ``permission_denied``
   * - The server does not implement an optional service.
     - ``unimplemented``

Underlay Discovery
^^^^^^^^^^^^^^^^^^

The ``UnderlayService`` allows endhosts to discover available transport
underlays in the local AS, including relevant information for them, such as,
border router addresses, interface identifiers, and direct port ranges.

RPC path: ``/scion.endhost.v1.UnderlayService/ListUnderlays``

This replaces the daemon ``AS``, ``Interfaces`` and ``PortRange`` RPCs. One
endhost API endpoint can serve more than one local AS. If ``isd_as`` is left
empty or set to 0, the requester wants the underlay information for all local
SCION ASes. If ``isd_as`` is set, the filter applies to all underlays.

.. code-block:: protobuf

  // ListUnderlaysRequest is used to discover available transport underlays.
  message ListUnderlaysRequest {
    // Include the underlays for the provided ISD-AS. This can be left empty or set to 0 which
    // indicates that the requester wants the underlay information for all possible local SCION ASes.
    optional uint64 isd_as = 1;
  }

  // ListUnderlaysResponse contains information about available underlays. At least one underlay
  // must be present for endhosts to use.
  message ListUnderlaysResponse {
    // The UDP/IP underlay of the AS.
    optional UdpUnderlay udp = 1;

    // The SNAP underlay of the AS.
    optional SnapUnderlay snap = 2;

    // Any future underlay goes here.
  }

  // The UDP/IP underlay consisting of the available SCION routers.
  message UdpUnderlay {
    repeated Router routers = 1;

    // The local ASes that this UDP/IP underlay serves. The list contains an AS
    // also if no router of the AS is available.
    repeated LocalAs local_ases = 2;
  }

  // LocalAs represents a local SCION AS of the UDP/IP underlay.
  message LocalAs {
    // The ISD-AS identifier.
    uint64 isd_as = 1;

    // The maximum size in bytes of a SCION packet (SCION headers and payload)
    // inside the AS.
    uint32 mtu = 2;
  }

  // Router represents a SCION routers internal interface and the associated SCION interface IDs.
  message Router {
    // The ISD-AS identifier
    uint64 isd_as = 1;

    // The UDP endpoint (host:port) of the internal interface.
    string address = 2;

    // The list of external SCION interface IDs on that router.
    repeated uint32 interfaces = 3;

    // PortRange is an inclusive range of ports. A range with start > end is empty.
    message PortRange {
      // The lowest port in the range.
      uint32 start = 1;
      // The highest port in the range.
      uint32 end = 2;
    }

    // The direct ports of the router. For a UDP/SCION packet with a destination port in
    // this range, the router uses the destination port as the UDP underlay port. For all
    // other ports, the router uses the well-known port 30041. If not set, all ports are
    // direct.
    PortRange direct_ports = 4;
  }

  // The SNAP underlay consisting of possibly multiple SNAPs.
  message SnapUnderlay {
    repeated Snap snaps = 1;
  }

  message Snap {
    // The address (host:port) of the SNAP control plane API. This can be the same
    // as the SCION endhost API endpoint.
    string address = 1;

    // The ISD-ASes of the SNAP.
    repeated uint64 isd_ases = 2;
  }

Each ``Router`` contains its ISD-AS, because interface IDs are unique only
inside one AS. The client finds the next hop of a path by the pair (ISD-AS,
interface ID).

The API does not require that a router serves more than one local AS. If an
implementation does this, the response contains one ``Router`` entry for each
AS, with the same address. How a router keeps the ASes apart is out of scope
for this document.

The ``local_ases`` field lists the local ASes of the UDP/IP underlay and their
MTU. The client uses the MTU for AS-local communication, because no path
segment exists for it. For paths to other ASes, the AS entries of the path
segments contain the MTU of each AS.

The ``Router`` message includes the ``direct_ports`` field to indicate
which port range the router supports for direct port dispatching. See
:doc:`router-port-dispatch` for background. The field has a new name, because
the default is the opposite of the default of ``dispatched_ports`` in
``topology.json``:

- If ``direct_ports`` is absent, all ports are direct.
- If ``dispatched_ports`` is absent in ``topology.json``, the range is empty.

The server translates ``dispatched_ports`` from ``topology.json`` into
``direct_ports``. If ``topology.json`` has no ``dispatched_ports``, the server
sends an explicit empty range. With this rule, the field can be removed when
all routers send all ports directly.

Path Segment Retrieval
^^^^^^^^^^^^^^^^^^^^^^

The ``SegmentsService`` provides paginated access to path segments (up, core, down)
that the client can combine to construct end-to-end paths. Returning segments
instead of pre-built paths enables client-side verification against the CP-PKI
and composability with segments from other sources.

RPC path: ``/scion.endhost.v1.SegmentsService/ListSegments``

This replaces the daemon ``Paths`` RPC.

.. code-block:: protobuf

  message ListSegmentsRequest {
    // The source ISD-AS of the final end-to-end path. This is most likely
    // the requester's own ISD-AS.
    uint64 src_isd_as = 1;

    // The destination ISD-AS the final end-to-end path.
    uint64 dst_isd_as = 2;

    // The maximum total number of segments to return, for up, core and
    // down segments together.
    // The service may return fewer than this value.
    // If unspecified, the maximum number of segments
    // per page is returned, which is 64. The service
    // uses 64 for a value above 64.
    int32 page_size = 3;

    // A page token, received from a previous
    // ListSegmentsRequest call.
    // Provide this to retrieve the subsequent page.
    // An empty token requests the first page.
    //
    // When paginating, all other parameters provided in
    // ListSegmentsRequest must match the call that provided
    // the page token.
    string page_token = 4;
  }

  // ListSegmentsResponse includes up, down, and core path segments that
  // can be combined to end-to-end paths.
  message ListSegmentsResponse {
      // The list of returned up path segments.
      repeated proto.control_plane.v1.PathSegment up_segments = 1;

      // The list of returned down path segments.
      repeated proto.control_plane.v1.PathSegment down_segments = 2;

      // The list of returned core path segments.
      repeated proto.control_plane.v1.PathSegment core_segments = 3;

      // The token for the next page of results. Empty on the last page.
      string next_page_token = 4;
  }

The response is empty, with an empty ``next_page_token``, in these cases:

- No path to the destination AS exists, or the destination AS is unknown.
- The source AS and the destination AS are the same. AS-local communication
  does not need path segments.

Pagination
""""""""""

- The **default page size** is 64 segments. The page size counts all segments
  together. The server selects the mix of up, core and down segments.
- Each page is **self-sufficient**: it contains enough segments to construct
  complete end-to-end paths without requiring segments from previous pages.
  This means **some segments may be repeated across pages**.
- Clients may discard segments from previous pages after processing them.
- **Pagination tokens** are short-lived references to server-side snapshots.
  Tokens have a limited lifetime (on the order of minutes). An expired token
  results in an ``invalid_argument`` error, and the client should restart
  pagination from the beginning.
- An empty ``next_page_token`` marks the last page. A request with an empty
  ``page_token`` returns the first page.

Ordering
""""""""

Segments are ordered by **priority**: higher-priority (more desirable)
segments are returned first.

Priority (desirability) is defined by server policy considering what client population is being served.
A typical policy (for average clients) returns the shortest and maximally diverse paths first.

The server may maintain different rankings for different client populations.
The first page contains the segments needed to construct the most desirable
end-to-end paths (for that client population).


Stitchability Guarantee
"""""""""""""""""""""""

If a path to the destination exists, the server ensures that the segments
returned on each page can be stitched into at least one complete end-to-end
path. This also applies if ``page_size`` is smaller than the number of segments
that this path needs. This guarantee applies per page, not across
pages. Nonetheless, clients can still stitch segments across pages to construct
alternative paths, but they may need to fetch multiple pages to obtain all the necessary segments.

TRC and Certificate Retrieval
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``TrustService`` provides access to TRCs and certificate chains, enabling
clients to verify path segments against the SCION CP-PKI.

The ``TrustService`` is an optional part of the endhost API. A server that does
not implement it returns ``unimplemented``. Certificates and TRCs are DER
encoded.

ListChains
""""""""""

RPC path: ``/scion.endhost.v1.TrustService/ListChains``

.. code-block:: protobuf

  // Request to fetch certificate chains for a given AS certificate subject.
  message ListChainsRequest {
    // The subjects for which the chains should be returned.
    repeated Subject subjects = 1;

    // Point in time at which the AS certificate must still be valid. In seconds
    // since UNIX epoch.
    uint32 at_least_valid_until = 2;

    // Point in time at which the AS certificate must be or must have been
    // valid. In seconds since UNIX epoch.
    uint32 at_least_valid_since = 3;

    // The maximum total number of chains to return.
    // The service may return fewer than this value.
    // If unspecified, the maximum number of chains
    // per page is returned, which is 64.
    int32 page_size = 4;

    // A page token, received from a previous
    // ListChainsRequest call.
    // Provide this to retrieve the subsequent page.
    // An empty token requests the first page.
    //
    // When paginating, all other parameters provided in
    // ListChainsRequest must match the call that provided
    // the page token.
    string page_token = 5;
  }

  message Subject {
    // ISD-AS of subject in the AS certificate.
    uint64 isd_as = 1;

    // SubjectKeyID in the AS certificate.
    bytes subject_key_id = 2;
  }

  message ListChainsResponse {
    // List of chains that match the request.
    repeated Chain chains = 1;

    // The token for the next page of results. Empty on the last page.
    string next_page_token = 2;
  }

  message Chain {
    // The subject corresponding to this chain.
    Subject subject = 1;

    // AS certificate in the chain.
    bytes as_cert = 2;

    // CA certificate in the chain.
    bytes ca_cert = 3;
  }

GetTrc
""""""

RPC path: ``/scion.endhost.v1.TrustService/GetTrc``

.. code-block:: protobuf

  // Request to fetch the TRC for a given ISD.
  message GetTrcRequest {
    // ISD of the TRC.
    uint32 isd = 1;

    // BaseNumber of the TRC identifying the version of the TRC
    // that forms the trust root of the TRC update chain. 0 means
    // use the highest known base version.
    uint64 base = 2;

    // SerialNumber of the TRC. Must be >= base. 0 means use the highest
    // known serial for a given base version.
    uint64 serial = 3;
  }

  message GetTrcResponse {
    // Raw TRC.
    bytes trc = 1;
  }

DRKey Retrieval
^^^^^^^^^^^^^^^

DRKey retrieval is an optional part of the endhost API. It reuses the existing
DRKey message format defined in `proto/daemon/v1/daemon.proto <https://github.com/scionproto/scion/blob/66ca97f817fd765ef796cb8764b0a81b7e14b1d3/proto/daemon/v1/daemon.proto#L226-L292>`_
(i.e., messages
``DRKeyASHostRequest``/``Response``, ``DRKeyHostASRequest``/``Response``,
``DRKeyHostHostRequest``/``Response``).

DRKey requests SHOULD be authenticated. The server uses client identity to
authorize key derivation. See the `Authentication`_ section for available
authentication mechanisms.

Obsoleted Daemon RPCs
^^^^^^^^^^^^^^^^^^^^^

The following daemon RPCs are obsoleted by the endhost API:

- ``AS`` -- Replaced by underlay discovery (``ListUnderlays``). The
  ``local_ases`` field of the UDP/IP underlay contains the local ISD-AS
  identifiers and the AS MTU. The core flag is not needed: the server splits a
  segment request into up, core and down segments, and the client combines the
  segments by their type and their end points.
- ``Interfaces`` -- Replaced by underlay discovery (``ListUnderlays``).
- ``Services`` -- Not needed. Endhosts interact exclusively with the endhost
  API endpoint; they do not need to discover individual infrastructure services.
- ``NotifyInterfaceDown`` -- Not needed. Endhosts perform their own path
  management and failover.
- ``PortRange`` -- Replaced by the ``direct_ports`` field in the
  ``Router`` message of the underlay discovery response.

Rationale
---------

Why ConnectRPC
^^^^^^^^^^^^^^

Note that ConnectRPC support was added to the control service in PR :issue:`4788`.
The motivation for it was described in the issue :issue:`4434`.
Most of the benefits described in the issue apply to the inter-AS RPCs, however as stated in the PR description,
intra-AS RPCs were moved to ConnectRPC on the server side, but client remained using gRPC/TCP since it was less urgent.

Now that we will implement a new API for endhosts, we have the opportunity to design it with ConnectRPC from the start, to:

  - Maintain consistency with the inter-AS APIs, which already use ConnectRPC.
  - Support several HTTP versions (1.1, 2, 3).


Why Segments Instead of End-to-End Paths
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Returning path segments instead of pre-built end-to-end paths provides several
advantages:

- **Client-side verification.** Clients can verify each segment's signatures
  against the CP-PKI, establishing trust in the path without relying on the
  server.
- **Composability.** Clients can combine segments from different sources (the
  endhost API, hidden path servers, sideloaded segments) to construct paths
  that a single server would not produce.
- **Flexibility.** Clients can implement their own path selection policies
  by choosing which segments to combine.

Why Self-Sufficient Pages
^^^^^^^^^^^^^^^^^^^^^^^^^

Making each page self-sufficient (containing enough segments to build complete
paths independently) simplifies client implementation. Clients do not need to
retain state from previous pages, and each page can be processed and discarded
in isolation. The trade-off is some segment repetition across pages, which will
cause some additional bandwidth usage and more complexity on clients which
want to discover additional paths.

Fast Common Case
^^^^^^^^^^^^^^^^

For the common case of "give me good paths to destination X", a single
``ListSegments`` request with the default page size returns the highest-priority
segments immediately. No additional round-trips, filter configuration, or
token management is required.

Compatibility
-------------

API Supporting Strategy (Incremental Deployment)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The transition from the daemon API to the endhost API happens in the
infrastructure, not in the client libraries. An AS that wants to support old
and new clients offers both APIs. An old client uses the daemon API, and a new
client uses the endhost API. Thus a client library does not need to support
both APIs.

Server-side
"""""""""""

The control service supports both the existing daemon API and the new endhost
API during the transition period. This can be done incrementally, and no coordination
between ASes is required.

Eventually, the daemon API is deprecated and removed.

Client-side
"""""""""""

A client library can support only the endhost API. Existing libraries and
their current status:

- **jpan** (Java) -- supports daemon and daemon-less operation.
- **snet** (Go) -- supports daemon and daemon-less operation.
- **scion-sdk (Rust)** -- supports new endhost API only.
- **csnet (C)** -- uses a direct control service interface.


SCION Daemon Transition
^^^^^^^^^^^^^^^^^^^^^^^

The SCION daemon is kept as a component during the transition period to
support existing applications. Once applications migrate to the endhost API
(either directly or through updated client libraries), the daemon can be
deprecated and similarly the old daemon API.

A caching proxy for the endhost API (similar in role to the current daemon)
may remain useful for deployments with many local applications, but it is not
a required component. Whether the daemon evolves into such a proxy or is
retired entirely is left to the implementation phase.

Implementation
--------------

Server-side
^^^^^^^^^^^

It is to be decided, how support for both APIs is implemented, e.g., both APIs (former
daemon API and new endhost API) may share backend logic
(path segment storage, trust material, DRKey derivation).


Client-side
^^^^^^^^^^^

Client libraries are updated to support the endhost API. Applications adopt the
new API by upgrading their library dependency. A library does not need to
support the daemon API, because an AS offers both APIs during the transition
(see `API Supporting Strategy (Incremental Deployment)`_).

Phased Roadmap
""""""""""""""

A high-level implementation roadmap (sequence order is not strictly defined, and some steps can be done in parallel):

1. **Proto definitions.** Define the ``scion.endhost.v1`` proto package and
   generate ConnectRPC bindings.
2. **Server implementation.** Implement the endhost API in the control service,
   sharing backend logic with the existing daemon API where possible.
3. **Client library updates.** Update snet and other libraries to support the
   endhost API, adding segment-based path construction and client-side
   verification.
4. **Daemon deprecation.** Once sufficient adoption is reached, deprecate and
   eventually remove the daemon API and the daemon component.
