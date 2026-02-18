*******************
SCION Endhost API
*******************

- Author(s): Samuel Hitz (main), Jordi Subirà-Nieto
- Last updated: 2026-02-11
- Discussion at: :issue:`4834`
- Status: **WIP**

Abstract
--------

This document proposes a new SCION Endhost API that replaces the current SCION
daemon gRPC API. The new API provides underlay discovery for multiple transport
types, segment-based path retrieval with pagination, cryptographic material for
client-side path verification, and optional DRKey key retrieval. It uses
`ConnectRPC <https://connectrpc.com/>`_ over HTTP with mandatory TLS server authentication.

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

- **Server authentication** via TLS is mandatory. The server certificate may
  be issued by a WebPKI CA or a private TLS PKI operated by the AS.
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

Underlay Discovery
^^^^^^^^^^^^^^^^^^

The ``UnderlayService`` allows endhosts to discover available transport
underlays in the local AS, including relevant information for them, such as,
border router addresses, interface identifiers, and dispatched port ranges.

RPC path: ``/scion.endhost.v1.UnderlayService/ListUnderlays``

This replaces the daemon ``Interfaces`` and ``PortRange`` RPCs. The ``AS``
RPC is also removed: if ``isd_as`` is left empty or set to 0,
it indicates that the requester wants the underlay information for all possible local SCION ASes

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
  }

  // Router represents a SCION routers internal interface and the associated SCION interface IDs.
  message Router {
    // The ISD-AS identifier
    uint64 isd_as = 1;

    // The UDP endpoint (host:port) of the internal interface.
    string address = 2;

    // The list of external SCION interface IDs on that router.
    repeated uint32 interfaces = 3;

    message PortRange{
        // The lowest port in the SCION/UDP dispatched port range.
        uint32 dispatched_port_start = 1;
        // The highest port in the SCION/UDP dispatched port range.
        uint32 dispatched_port_end = 2;
    }

    // The dispatched port range supported by the router. UDP/SCION packets with a destination
    // port within this range will be sent to the same UDP destination port on the destination host.
    // For other ports, the router will use the well-known dispatcher port (30041). If not set,
    // the entire port range is assumed to be dispatched.
    PortRange dispatched_range = 4;
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


The ``Router`` message includes the ``dispatched_range`` field to indicate
which port range the router supports for direct port dispatching. If absent,
the client should assume all ports are dispatched. See :doc:`router-port-dispatch`
for background on dispatched port ranges.

Path Segment Retrieval
^^^^^^^^^^^^^^^^^^^^^^

The ``PathService`` provides paginated access to path segments (up, core, down)
that the client can combine to construct end-to-end paths. Returning segments
instead of pre-built paths enables client-side verification against the CP-PKI
and composability with segments from other sources.

RPC path: ``/scion.endhost.v1.PathService/ListSegments``

This replaces the daemon ``Paths`` RPC.

.. code-block:: protobuf

   message ListSegmentsRequest {
    // The source ISD-AS of the final end-to-end path. This is most likely
    // the requester's own ISD-AS.
    uint64 src_isd_as = 1;

    // The destination ISD-AS the final end-to-end path.
    uint64 dst_isd_as = 2;

    // The maximum total number of segments to return.
    // The service may return fewer than this value.
    // If unspecified, the maximum number of segments
    // per page is returned, which is 64.
    int32 page_size = 3;

    // A page token, received from a previous
    // ListSegmentsRequest call.
    // Provide this to retrieve the subsequent page.
    //
    // When paginating, all other parameters provided in
    // ListSegmentsRequest must match the call that provided
    // the page token.
    string page_token = 4;
  }
  // ListSegmentsReponse includes up, down, and core path segments that
  // can be combined to end-to-end paths.
  message ListSegmentsResponse {
      // The list of returned up path segments.
      repeated proto.control_plane.v1.PathSegment up_segments = 1;

      // The list of returned down path segments.
      repeated proto.control_plane.v1.PathSegment down_segments = 2;

      // The list of returned core path segments.
      repeated proto.control_plane.v1.PathSegment core_segments = 3;

      // The token for the next page of results.
      string next_page_token = 4;
  }

Pagination
""""""""""

- The **default page size** is 64 segments.
- Each page is **self-sufficient**: it contains enough segments to construct
  complete end-to-end paths without requiring segments from previous pages.
  This means **some segments may be repeated across pages**.
- Clients may discard segments from previous pages after processing them.
- **Pagination tokens** are short-lived references to server-side snapshots.
  Tokens have a limited lifetime (on the order of minutes). An expired token
  results in an error response, and the client should restart pagination from
  the beginning.

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

The server ensures that the segments returned on each page can be stitched
into at least one complete end-to-end path. This guarantee applies per page, not across
pages. Nonetheless, clients can still stitch segments across pages to construct
alternative paths, but they may need to fetch multiple pages to obtain all the necessary segments.

TRC and Certificate Retrieval
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``TrustService`` provides access to TRCs and certificate chains, enabling
clients to verify path segments against the SCION CP-PKI.

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
  }

  message Subject {
    // ISD-AS of subject in the AS certificate.
    uint64 isd_as = 1;

    // SubjectKeyID in the AS certificate.
    bytes subject_key_id = 2;
  }

GetTrc
""""""

RPC path: ``/scion.endhost.v1.TrustService/GetTrc``

.. code-block:: protobuf

  // Request to fetch the TRC for a given ISD.
  message TRCRequest {
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
  message TRCResponse {
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

- ``AS`` -- The local ISD-AS identifier, core flag, and MTU is omitted from the endhost API.
- ``Interfaces`` -- Replaced by underlay discovery (``ListUnderlays``).
- ``Services`` -- Not needed. Endhosts interact exclusively with the endhost
  API endpoint; they do not need to discover individual infrastructure services.
- ``NotifyInterfaceDown`` -- Not needed. Endhosts perform their own path
  management and failover.
- ``PortRange`` -- Replaced by the ``dispatched_range`` field in the
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

Server-side
"""""""""""

The control service supports both the existing daemon API and the new endhost
API during the transition period. This can be done incrementally, and no coordination
between ASes is required.

Eventually, the daemon API is deprecated and removed.

Client-side
"""""""""""

Each client library defines its own backward-compatibility policy. Existing
libraries and their current status:

- **jpan** (Java) -- supports daemon and daemon-less operation.
- **snet** (Go) -- supports daemon and daemon-less operation.
- **scion-sdk (Rust)** -- supports new endhost API only.
- **csnet (C)** -- uses a direct control service interface.


API Versioning Strategy
^^^^^^^^^^^^^^^^^^^^^^^

**[OPEN]** API versioning is related to :issue:`4832`. The expectation is that
an explicit versioning strategy extends the API but does not modify the core
design described here. Defining the versioning strategy is not a blocker for
this design document.

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
new API by upgrading their library dependency.

**[OPEN]** Whether libraries maintain backward compatibility with the old
daemon API or only support the new endhost API is left to each library's
policy.

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
