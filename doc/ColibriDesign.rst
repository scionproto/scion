**************
COLIBRI Design
**************


About This Document
===================
COLIBRI is a quality-of-service (QoS) system for SCION. This brief design
document is based on the thesis by Dominik Roos entitled "COLIBRI: A
Cooperative Lightweight Inter-domain Bandwidth Reservation Infrastructure".
In this document, we will explain the core ideas of COLIBRI and the differences
from that thesis.

This document will briefly discuss how the COLIBRI packets are forwarded,
and how the same type of COLIBRI packets are used to transport the
control-plane traffic.
This document will dig deeper in the COLIBRI service itself and give a more
detailed view of the operations it will perform for the control plane
to work.


Components
==========
There are four main components that need to be modified or created: the
COLIBRI service itself, the border router, a monitoring system, and
``sciond`` in the end host:

COLIBRI Service
    Enables the COLIBRI control plane. Used to negotiate both segment and
    end-to-end reservations.

Border Router
    Needs to process COLIBRI packets differently than SCION packets and forward
    the COLIBRI traffic with higher priority than best effort.

Monitoring
    Does the accounting and policing. It monitors per flow packets when
    originating in this AS, or stateless when they are only transit.

sciond
    Needs to expose a COLIBRI *API*. Needs to manage end-to-end reservations on
    behalf of the applications.


Data & Control-Plane Transport
==============================
Nomenclature:

Reservation index
    For any reservation (whether segment or end-to-end, see below) to be used,
    it is necessary to have one (and only one) active index.
    An index is just a "version" of the reservation, that **cannot** modify
    its path. However, it can modify the reserved bandwidth, as well as other
    properties of the reservation.

Segment reservation
    A reservation between two ASes. This is a "tube" that allows to communicate
    control-plane traffic directly, or to embed one or multiple end-to-end
    reservations inside. There is only one segment reservation possible per
    any given SCION path segment.
    All segment reservations have a unique ID.
    A segment reservation can be of type up, down, core, peering-up, or
    peering-down. Up, down, and core are similar to the corresponding regular
    SCION segments; peering-up and peering-down end or start with a peering link,
    respectively.
    All segment reservations have a maximum set of 16 indices.

End-to-end (E2E) reservation
    A reservation between two end hosts. It is used to send data traffic. It
    uses from one to three segment reservations to reach the destination end
    host (similar to regular SCION paths). The E2E reservation "stitches" these
    segment reservations to create a valid E2E reservation.
    Each E2E reservation has its own unique ID. There is only one possible E2E
    reservation per sequence of segment reservation, and thus, per SCION path.
    The path type of an E2E reservation is always the same (type *E2E*)
    An E2E reservation has a maximum set of 16 indices.

There is only one type of COLIBRI packet. It is mainly used by the data plane
to transport user data in E2E reservations between end-host machines.
But this COLIBRI packet is also used by the COLIBRI service when it needs to
transport requests and responses between COLIBRI services in different ASes.
The advantage of this decision is the simplicity of the treatment of the
COLIBRI packets in the border router.

Design Requirements
-------------------
#. The monitoring computes the bandwidth usage per segment reservation.
   It relies on deriving the segment reservation ID for each packet without
   keeping any state.
#. The border router must validate and forward the packets very quickly.
   For this, as mentioned before, we have only one COLIBRI packet type,
   and no hop-by-hop extensions. This means that the control-plane traffic
   uses the same transport mechanism.
#. The border router must be able to check the validity of each packet without
   keeping state. This requires cryptographic mechanisms built on a small set
   of private keys (typically one) and no other state.

Design Decisions
----------------
According to the requirements exposed above, here are some of the decisions
taken to fulfill them:

#. Each packet contains at least one reference to a segment reservation ID.
   We will then include the lengths of the (possibly) three stitched segments,
   alongside with their reservations IDs.
   The monitoring (or any other) system can then deduce which is the current
   segment reservation being used. For example, :math:`[2,3,2]` means we
   expect 2 ASes in the up-segment, 3 in the core-segment, and 2 in the
   down-segment. Note that the last AS in the up-segment is the same as the
   first in the core-segment, and that the last AS of the core-segment is the
   same as the first AS of the down-segment.
#. A COLIBRI path is composed of one mandatory *InfoField* and a sequence of
   *HopFields*. This applies to both segment and E2E reservations. The
   *InfoField* controls what the border router can do with the packet:

   - Each COLIBRI packet can be used as if it had a hop-by-hop extension
     inside. This allows control traffic, which must always stop at each
     COLIBRI service, to be sent using COLIBRI packets.
     This is done via a ``Control (C)`` flag.
     These packets are always delivered to the local COLIBRI anycast address
     by the border router.
   - Each packet distinguishes the type of reservation via a flag in its
     *InfoField*. This allows a packet to have either a segment or an E2E
     reservation. This is the ``Segment (S)`` flag. It forces the ``C`` to
     be also set (only control traffic is allowed on segment reservations).
   - A COLIBRI packet can reverse its path, via the ``Reverse (R)`` flag.
     This flag forces the ``C`` flag to be set (only control traffic is
     allowed to travel on the reverse path).
     Via this flag, we can always send the responses to the requests that
     the COLIBRI services receive. The responses always travel in the
     reverse direction, and must always stop at each COLIBRI service.

#. The cryptographic tag enabling packet validation for an AS relies only on a
   private key derived from secret AS values (e.g., the master key), and fields
   present in the packet.


MAC Computation
---------------
A message-authentication code (MAC) is used in the validation of a packet when
it is being forwarded.
It protects the path in two ways:

- Values of the InfoField and HopFields cannot be altered.
- HopFields must be used in the right order they were provided.
  I.e., a HopField that was obtained in a path as the `i`-th one,
  must always be used in the `i`-th position.

.. Note::
    The ``R`` flag we chose at the `design decisions`_
    alters the order of appearance of the HopFields, but not the
    computation of the MAC. Since ``R`` implies ``C``, each COLIBRI service
    can (and possibly will) check that the ingress/egress pair they observe
    in their HopField corresponds to that stored in their DB for the
    reservation ID of the packet.

To achieve the protection we want against changes in the relevant parts
of the *InfoField* and *HopField*, we will include the following in the
MAC computation:

- Reservation ID: because there can be at most one reservation per path, and
  each reservation is identified by an ID, the ID also identifies the path.
  This means that we will no longer need to onion the HopFields or include
  any type of index to protect their order.
- Reservation fields: fields that came from the reservation setup, and that
  should not be altered otherwise, must be included in the MAC computation.
  This prevents malicious clients from tampering with the reservation and
  claiming more reserved bandwidth than what they were granted.
  These fields are:

  - Expiration time.
  - Granted bandwidth.
  - Request latency class.
  - Index number.
  - Reservation path type (up, core, etc.)
  - The lengths of the (up to three) stitched segments.
  - The segment IDs of the (up to three) stitched segments.

- Finally the ingress and egress interface IDs of the particular AS computing
  the MAC.

We also want to protect ASes from being wrongly blamed for consuming more than
their granted bandwidth by other malicious ASes that pursue to have them
blacklisted.
To do this we will use a per-packet MAC computation approach.
This is done by computing two different types of MACs: the *static* MACs and
the *per-packet* MACs.

Let's call *A* the source of the reservation, and *B* an
AS in the path of said reservation. :math:`K_B` is a secret key that only
*B* knows. *MAC* is the function used to compute the MAC. *InputData* are
all the fields specified above, that will be part of the MAC computation.
The **static MAC** is computed as:

.. math::
    \sigma_B = \text{MAC}_{K_B}(InputData)

That static MAC does not change with the payload of the packet. We will
communicate each of the :math:`\sigma_B` for each AS *B* part of the path, to
AS *A* (the source of the reservation), in the reservation setup process, but
encrypted only for *A*, e.g. with the public AS key or using DRKey.
The AS *A* will store these static MAC results as keys to use in the
per-packet MAC computation.

Every time a new packet is sent using that COLIBRI reservation,
the per-packet MACs have to be computed. We denote the per-packet MACs as *HVF*
(hop-validation field) and introduce a high-precision time stamp of each
packet, *TS*.
The **per-packet MAC** (HVF) is computed as follows:

.. math::
    \text{HVF}_B = \text{MAC}_{\sigma_B}(TS, \text{packet_length}, \text{flags})

The `flags` refer to the COLIBRI packet flags (``C,R,S``).
Note that the key used to compute the HVF is :math:`\sigma_B`, the static
MAC computed by *B*, which is only known to *B* and *A*.

For the sake of simplicity let's say that this computation happens in a
specific service only for this purpose, that receives COLIBRI traffic from
the local end hosts, checks their permissions, and then computes the HVF
that go in the packet.

If, at a later moment, the HVF computed for a packet while in transit
at *B* is correct, *B* knows that only *A* could have actually computed it,
since the :math:`\sigma_B` was not even given to end hosts, but only
*official* services of A.

TODO: do we really need the index number included in the MAC ?

Forwarding
----------
TODO


Control-Plane General Overview
==============================
Because the ``C`` flag makes a COLIBRI packet to stop at every COLIBRI
service along the reservation path, the requests can be sent
using a normal COLIBRI packet with ``C=1``. The responses will be sent
by the COLIBRI service using ``C=1`` and ``R=1``. This applies for both
segment and E2E reservation operations, and thus depending on the type,
the flag ``S`` will be set or not.

This delivery mechanism cannot be abused, as every border router must check
that if any of the ``R`` or ``S`` flags are set, ``C`` is also set. And
if ``C`` is set, the bourder router must deliver the packet
to the local COLIBRI service. The COLIBRI
service must always check when handling the request or response, that the
path used in the packet is valid. I.e., it contains the correct sequence of
HopFields in the path, compared to the data it has in its DB. This is doable
because these operations are done in the control plane,
which is not as performance critical as the data plane.

E2E Reservation Renewal Operation
---------------------------------
For convenience, we provide the trace of an E2E reservation renewal. This
example has the following values:

- Reservation originator: end host :math:`h_1` in AS *A*
- Reservation destination: end host :math:`h_2` in AS *G*
- E2E reservation ID: :math:`\text{E2E}_{(A,1111)}`
- The reservation stitches 3 segment reservations:

  - Up: :math:`A \rightarrow B \rightarrow C`,
    with ID :math:`\text{Seg}_{(A,1)}`
  - Core: :math:`C \rightarrow D \rightarrow E`,
    with ID :math:`\text{Seg}_{(C,1)}`
  - Down: :math:`E \rightarrow F \rightarrow G`,
    with ID :math:`\text{Seg}_{(E,1)}`

#. The host :math:`h_1` in *A* decides to renew the reservation. For this it
   sends a request to the COLIBRI service at *A*.
   The packet has the path :math:`\verb!C=1,R=0,S=0!`,
   :math:`A \rightarrow B \rightarrow C \rightarrow D
   \rightarrow E \rightarrow F \rightarrow G`
   All the static MACs :math:`\sigma_X` were provided in a previous setup of
   the reservation.
#. The service at *A* handles the request. It does the admission
   in *A*. Modifies the payload conveniently and sends a message to the next
   hop, which is *B*. TODO: how is the payload modified?
#. The border router at *A* forwards the packet to *B*
#. The border router at *B* validates its HopField. It is correct (flags are
   not used for the MAC). The ``C`` flag is set, so the border router delivers
   it to the COLIBRI service.
#. The COLIBRI service handles the request and does the admission. It is
   admitted and the payload is modified accordingly.
   The COLIBRI service sends the message to the next hop, which is C.
#. The process continues on this way until there is an error or the request
   reaches the last AS `G`.

   - If there is an error, the payload is modified, and
     the message is sent in reverse. This means ``R=1,C=1``. It will
     traverse the path in reverse until it reaches `A`, where it will be
     finally forwarded to :math:`h_1`, the reservation originator.
   - If there are no errors, the request will reach AS `G`. There the
     admission is computed in the COLIBRI service, and it will be forwarded
     to the destination end host :math:`h_2`. The end host will decide the
     admission of the reservation and respond to its AS's COLIBRI service.

#. Assuming the request was admitted all the way up to the destination end-
   host :math:`h_2`, this will reverse the traversal of the path by setting
   ``R=1,C=1`` and send it to its AS's COLIBRI service.
#. The COLIBRI service at `G` receives the response with acceptance, and then
   it adds the HopField to the payload. It also computes the MAC
   :math:`\sigma_G` and encrypts and authenticates it with
   :math:`DRKey K_{G \to A}`. The MAC is
   also added to the payload. The packet is sent to the border router at `G`.
#. The border router at `G` receives the COLIBRI packet with ``R=1,C=1``,
   and forwards it to the next border router, at `F`.
#. The border router at `F` receives the packet. It checks whether the MAC
   is valid and drops the packet if not. If the MAC is
   valid (MAC is independent of the flags), the border router delivers it
   to the local COLIBRI service.
#. The COLIBRI service at `F` now add its own HopField and :math:`\sigma_F`,
   encrypted with the public key of `A`. It then sends it to the border router.
#. The process continues until the packet reaches the COLIBRI service at `A`,
   where the HopFields inside are decrypted and stored so that COLIBRI
   traffic originating for this reservation can be correctly stamped with the
   per-packet MAC.

TODO Question: how is `G` sending back the packet with the per-packet MAC schema?
Proposed: use HVF only when C=0, and static MACs when C=1. This should be okay,
as every request comes source authenticated with DRKey, and stops at every COLIBRI service.

TODO Question: we want to have reliable communication between services. This means using
quic for the communication. Will it work okay?

Down-Segment Renewal Operation
------------------------------
The segment reservation operations look very much like the previous example,
with the peculiarity of having the ``S=1`` flag. It is of special interest to
check the case of a down-segment reservation renewal, as it has to originate
in what would later be the destination AS. I.e. if the core AS is `E`, and
the path we want to reserve is :math:`E \rightarrow F \rightarrow G`,
the renewal is requested from G, but sent first to `E`.
These are the steps:

#. The COLIBRI service at `G` decides to renew the down-segment reservation.
   It has the ID :math:`\text{Seg}_{(E,1)}`. The path of the reservation is
   :math:`\verb!C=1,R=1,S=1!, E \rightarrow F \rightarrow G`. This is because
   the first step is sending it from `G` to `E`. So `G` reverses the path and
   computes the admission **in reverse**.
   `G` then sends the packet to the border router.
#. The border router at `G` sees the packet with ``R=1`` incoming via its
   local interface. It will validate the packet and forward it to the next
   border router, at `F`.
#. The border router at `F` receives the packet via the remote interface with
   `G`. It validates the MAC successfully, as well as the rest of the fields.
   Since ``C=1`` it delivers it to the local COLIBRI service.
#. The COLIBRI service computes the admission, again **in reverse** and
   updates the request with the admission values. It then sends
   the packet to the border router again, to be forwarded.
#. Similarly to the previous steps, the packet finally arrives to the local
   COLIBRI service at `E`. It does the admission **in reverse** and, since this
   is the last AS in the path, it adds its HopField and :math:`\sigma_E`
   to the payload and it switches direction by setting ``R=0``.
   Now the packet is sent back to the border router to be forwarded to the
   next hop.
#. The packet is now traveling in the direction of the reservation, and
   arrives to the border router at `F`. This border router validates the
   packet and sends it to the local COLIBRI service.
#. The COLIBRI service at `F` receives the packet and adjusts in its DB the
   values for the reservation. It adds its HopField and MAC and
   sends the packet again to the border router, to continue its journey.
#. The packet arrives to the border router at `G`, and since it has the flag
   ``C=1`` it delivers it to the local COLIBRI service, after validating that
   the MAC and the rest of the fields are okay.
#. Finally, the COLIBRI service at `G` receives the packet and stores the
   HopFields and MACs from the payload.

TODO Question: in the case of a down-segment, who is storing the :math:`\sigma_X` ?
Should that be the originator, i.e. `G` ? or the first AS in the direction of the traffic, i.e. `F` ?


COLIBRI Service
===============
The COLIBRI Service manages the reservation process of the COLIBRI QoS
subsystem in SCION. It handles both the segment and E2E reservations
(formerly known as steady and ephemeral reservations).

The COLIBRI service is structured similarly to
other existing Go infrastructure services. It reuses the following:

- `go/lib/env`: Is used for configuration and setup of the service.
- `go/pkg/trust`: Is used for crypto material.
- `go/lib/infra`: Is used for the messenger to send and receive messages.
- `go/lib/periodic`: Is used for periodic tasks.

The COLIBRI service is differentiated into these parts:

* **configuration** specifying admission and reservation parameters for this AS,
* **handlers** to handle incoming reservation requests (creation,
  tear down, etc.),
* **periodic tasks** for segment reservation creation and renewal,
* **reservation storage** for partial and committed reservations.

.. image:: fig/colibri/COS.png


Operations for Segment Reservations
-----------------------------------
In general, all the requests travel from :math:`\text{AS}_i`
to :math:`\text{AS}_{i+1}`, where :math:`\text{AS}_{i+1}` is the next AS
to :math:`\text{AS}_i` in the direction of the reservation.

Responses travel in the reverse direction: from :math:`\text{AS}_{i+1}` to
:math:`\text{AS}_i`.

The exception to this are the down-segment reservations.
The down-segment reservation requests travel (with ``R=1``) from the
reservation destination to the reservation initial AS
(:math:`\text{AS}_n \to \text{AS}_{n-1} \to \ldots \text{AS}_0`).
This is done this way because the operation initiator will always be the
reservation destination.
So in a setup :math:`A \leftarrow B \leftarrow C`
where `A` is the final destination of the reservation,
it will also be `A` the AS to initiate the setup/renewal process,
by sending a request using an existing reservation (if it exists) and ``R=1``.
The same reasoning applies to the responses, that travel from
:math:`\text{AS}_i` to :math:`\text{AS}_{i+1}`.
In the example above, they would travel from `C` to `A`, with ``R=0``.

Setup a Segment Reservation
***************************
The configuration specifies which segment reservations should be created from
this AS to other ASes. Whenever that configuration changes, the service
should be notified.

#. The service triggers the creation of a new segment reservation at
   boot time and whenever the segment reservation configuration file changes.
#. The service reads the configuration file and creates a segment reservation
   request per each entry.

   - The path used in the request must be obtained using the *path predicate*
     in the configuration.

#. The store in the COLIBRI service saves the intermediate request and
   sends the request to the next AS in the path.
#. If there is a timeout, this store will send a cleanup request to the
   next AS in the path.


Handle a Setup Request
**********************
#. The COLIBRI service store is queried to admit the segment reservation.
#. The store decides the admission for the reservation (how much bandwidth).
   It uses the *traffic_matrix* from the configuration package.
#. The store saves an intermediate reservation entry in the DB.
#. If this AS is the last one in the path, the COLIBRI service store saves the
   reservation as final and notifies the previous AS in the path with a
   reservation response.
#. The store forwards the request with the decided bandwidth.

Handle a Setup Response
***********************
#. The store saves the reservation as final.
#. If this AS is the first one in the reservation path (aka
   *reservation initiator*), the store sends an index confirmation request
   to the next AS in the path.
#. If this AS is the not the first one in the reservation path, the store
   sends a response message to the previous AS's COLIBRI service.

Handle an Index Confirmation Request
************************************
#. The store in the COLIBRI service checks that the appropriate reservation
   is already final.
#. The store modifies the reservation to be confirmed
#. The COLIBRI service forwards the confirmation request.

Handle a Cleanup Request
************************
#. The COLIBRI service removes the referenced reservation from its store.
#. The COLIBRI service forwards the cleanup request.

Handle a Teardown Request
*************************
#. The COLIBRI service checks the reservation is confirmed but has no
   allocated E2E reservations.
#. The COLIBRI service checks there are no telescoped reservations using
   this segment reservation.
#. The store removes the reservation.
#. The COLIBRI service forwards the teardown request.

Handle a Renewal Request
************************
The renewal request handler is the same as the `handle a setup request`_.
The renewal is initiated differently (by adding a new index to an existing
reservation), but handled the same way.

Renew a Segment Reservation
***************************
#. The service triggers the renewal of the existing segment reservations
   with constant frequency.
#. The store in the COLIBRI service retrieves each one of the reservations
   that originate in this AS.
#. Per reservation retrieved, the store adds a new index to it and
   pushes it forward.

Handle a Reservation Query
**************************
#. The store in the COLIBRI service receives the query and returns the
   collection of segment reservations matching it.

Operations for E2E Reservations
-------------------------------

Handle an E2E Setup Request
***************************
#. The COLIBRI service queries the store to admit the reservation
#. The store computes the allowed bandwidth (knowing the current segment
   reservation and the existing E2E reservations in it).
#. The store pushes forward the setup request.

Handle an E2E Renewal Request
*****************************
The renewal request handler is the same as the `handle an e2e setup request`_.

Handle an E2E Cleanup Request
*****************************
#. The COLIBRI service removes the request from its store.
#. The COLIBRI service forwards the cleanup request.

Interfaces of the COLIBRI Service
---------------------------------
Main interfaces of the service.

The Reservation Store in the COLIBRI service keeps track of the reservations
created and accepted in this AS, both segment and E2E.
The store provides the following interface:

.. code-block:: go

    type ReservationStore {
        GetSegmentReservation(ctx context.Context, id SegmentReservationID) (SegmentReservation, error)
        GetSegmentReservations(ctx context.Context, validTime time.Time, path []InterfaceId]) ([]SegmentReservation, error)

        AdmitSegmentReservation(ctx context.Context, req SegmentReservationReq) error
        ConfirmSegmentReservation(ctx context.Context, id SegmentReservationID) error
        CleanupSegmentReservation(ctx context.Context, id SegmentReservationID) error
        TearDownSegmentReservation(ctx context.Context, id SegmentReservationID) error

        AdmitE2EReservation(ctx context.Context, req E2EReservationReq) error
        CleanupE2EReservation(ctx context.Context, id E2EReservationID) error
    }

The `sciond` end-host daemon will expose the *API* that enables the use
of COLIBRI by applications:

.. code-block:: go

    type sciond {
        ...
        AllowIPNet(ia IA, net IPNet) error
        BlockIPNet(ia IA, net IPNet) error
        WatchSegmentRsv(ctx context.Context, pathConf PathConfiguration) (WatchState, error)
        WatchE2ERsv(ctx context.Context, resvConf E2EResvConfiguration) (WatchState, error)
        // WatchRequests returns a WatchState that will notify the application of any COLIBRI e2e request ending here.
        WatchRequests() (WatchState, error)
        Unwatch(watchState WatchState) error
    }

Reservation DB
--------------
There are two main parts in the DB: the segment reservation entities, and the
end-to-end entities.
To link the E2E reservations to the appropriate segment ones,
a table is used.

There are no restrictions of cardinality other than uniqueness and non
null-ness for some fields, but nothing like triggers on insertion are used.
E.g. it is technically possible to link more than three segment reservations
with a given E2E one. These cardinality restrictions are enforced
by code.

.. image:: fig/colibri/DB.png

Furthermore, there are some indices created to speed up lookups:

* seg_reservation
    * id_as,suffix
    * ingress
    * egress
    * path
* seg_index
    * reservation,index_number
* e2e_reservation
    * reservation_id
* e2e_index
    * reservation,index_number
* e2e_to_seg
    * e2e
    * seg
