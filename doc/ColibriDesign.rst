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
    reservations inside.
    A segment reservation can be of type up, down, core, peering-up, or
    peering-down. Up, down, and core are similar to the corresponding regular
    SCION segments; peering-up and peering-down end or start with a
    peering link, respectively.
    All segment reservations have a maximum set of 16 indices.

End-to-end (E2E) reservation
    A reservation between two end hosts. It is used to send data traffic. It
    uses from one to three segment reservations to reach the destination end
    host (similar to regular SCION paths). The E2E reservation "stitches" these
    segment reservations to create a valid E2E reservation.
    The path type of an E2E reservation is always the same (type *E2E*)
    An E2E reservation has a maximum set of 16 indices.

Reservation ID
    Segment and E2E reservations have a reservation ID. It uniquely identifies
    the reservation. The reservation ID must be unique on the path (path
    understood as a sequence of interface IDs).
    Both segment and E2E reservation IDs contain the AS ID of the reservation
    originator AS as the first 6 bytes.

There is only one type of COLIBRI packet. It is mainly used by the data plane
to transport user data in E2E reservations between end-host machines.
But this COLIBRI packet is also used by the COLIBRI service when it needs to
transport requests and responses between COLIBRI services in different ASes.
The advantage of this decision is the simplicity of the treatment of the
COLIBRI packets in the border router.

Design Requirements
-------------------
#. The monitoring computes the bandwidth usage per E2E reservation.
   This relies on the control-plane not invalidating any reservation until its
   expiration time (what is valid in the data-plane is valid in the
   control-plane).
   The monitoring system must be able to catch E2E reservations over-usage and
   double usage with high probability, without keeping any state.
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

#. The COLIBRI packet does not need segment IDs in it.
   Since the E2E reservations are the only ones monitored,
   the monitor does not need the segment IDs, and the COLIBRI packets that
   carry segment reservation operations data belong to the control-plane and
   can be policed there, we will not need to refer to the stitched segments
   when the packet uses an E2E reservation.
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
     The bandwidth is also guaranteed when ``R=1``.

#. The cryptographic tag enabling packet validation for an AS relies only on a
   private key derived from secret AS values (e.g., the master key), and fields
   present in the packet.


.. _colibri-mac-computation:

MAC Computation
---------------
A message-authentication code (MAC) is used in the validation of a packet when
it is being forwarded.
It protects the path in two ways:

- Values of the InfoField and HopFields cannot be altered.
- HopFields must be used in the right order they were provided.
  I.e., a HopField that was obtained in a path as the `i`-th one,
  must always be used in the `i`-th position.
- The number of HopFields is unaltered.

To achieve the protection we want against changes in the relevant parts
of the *InfoField* and *HopField*, we will include the following in the
MAC computation:

- Reservation ID: as each HopField's MAC is bound to the unique
  reservation ID, it is impossible to "splice" reservations, i.e.,
  combine HopFields from multiple reservations. Therefore, the
  MAC chaining employed in standard SCION is not needed
  (note that an ID is bound to exactly one path).
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

- Other fields of the *InfoField* related to the path that should
  not be altered:

  - The ``C`` flag.
  - The number of ASes in the path.

- Finally the ingress and egress interface IDs of the particular AS computing
  the MAC.

.. Note::
    The ``R`` flag we chose at the `design decisions`_
    alters the order of appearance of the HopFields, but not the
    computation of the MAC. Since ``R`` implies ``C``, each COLIBRI service
    can (and possibly will) check that the ingress/egress pair they observe
    in their HopField corresponds to that stored in their DB for the
    reservation ID of the packet.

    The ``S`` flag is also not part of the MAC computation, and since it forces
    ``C=1`` we can follow the same principle described above and ensure in
    the COLIBRI service that the packet represents a valid segment reservation.

As it can be noted, two sets of MAC values will be produced depending on the
value of the flag ``C``. For ``C=1`` the MAC is computed and used directly in
the HopFields.

But when ``C=0``, we want to avoid end hosts from the source of the reservation
AS *A* being able to leak the MACs to other entities in different ASes,
that could then generate traffic
that appears like generated from the original AS *A*, and thus AS *A*
being wrongly blamed for consuming more than their granted bandwidth,
which would surely have it blacklisted in the transit ASes.
To do this we will use a per-packet MAC computation approach.
This is done by computing a different type of MAC:
the *per-packet* MAC.

Let's call *A* the source of the reservation, and *B* an
AS in the path of said reservation. :math:`K_B` is a secret key that only
*B* knows. *MAC* is the function used to compute the MAC. *InputData* are
all the fields specified above, that will be part of the MAC computation.
Let's describe both MACs. The **static MAC** is used when ``C=1``:

.. math::
    \text{MAC}_B^{C=1} = \text{MAC}_{K_B}(InputData)

With ``C=0``, the **per-packet MAC** has to be computed.
We denote the per-packet MACs as *HVF* (hop-validation field)
and introduce a high-precision time stamp of each
packet, *TS*.
The (HVF) is computed as follows:

.. math::
    \begin{align}
    \sigma_B &= \text{MAC}_B^{C=0} \\
    \text{HVF}_B &= \text{MAC}_{\sigma_B}(\text{TS}, \text{packet_length}) \\
    \end{align}

Note that the key used to compute the HVF is :math:`\sigma_B`, the static
MAC computed by *B*, which is only known to *B* and *A*.

The MAC values when ``C=1`` are communicated in the successful response
of a reservation setup or renewal, without any type of encryption.
In the same response message, we
add each of the :math:`\sigma_B` for each AS *B* part of the path, but
encrypted only for *A*, e.g. using DRKey.
The AS *A* will store both the static :math:`\text{MAC}_X^{C=1}`
as well as the :math:`\sigma_B` values, that will be used as keys in the
per-packet MAC computation.

For the sake of simplicity let's say that this computation happens in a
specific service only for this purpose, that receives COLIBRI traffic from
the local end hosts, checks their permissions, and then computes the HVF
that go in the packet.

If, at a later moment, the HVF computed for a packet while in transit
at *B* is correct, *B* knows that only *A* could have actually computed it,
since the :math:`\sigma_B` was not ever given to end hosts, but only
to the *official* service of AS *A*.


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
if ``C`` is set, the border router must deliver the packet
to the local COLIBRI service.
The COLIBRI service checks the source validity on each operation via
DRKey tags inside the payload, that authenticate that the source is
is indeed requesting this operation.

Since all control-plane operations have ``C=1``, they use the static MAC.

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
#. The COLIBRI service at *A* handles the request. It does the admission
   in *A*. Modifies the payload conveniently and sends a message to the next
   hop, which is *B*.
   All the static MACs :math:`\text{MAC}_X^{C=1}` were provided in
   a previous setup of the reservation and stored in the service.
   TODO: how is the payload modified?
#. The border router at *A* forwards the packet to *B*
#. The border router at *B* validates its HopField. It is correct.
   The ``C`` flag is set, so the border router delivers
   the packet to the COLIBRI service.
#. The COLIBRI service at *B* handles the request and does the admission.
   It is admitted and the payload is modified accordingly.
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
   it adds the HopField to the payload. It also computes both MACs
   :math:`\text{MAC}_G^{C=1}` and :math:`\text{MAC}_G^{C=0}` (which is
   :math:`\sigma_G`) and encrypts and authenticates this last one with
   :math:`DRKey K_{G \to A}`. Both MACs are
   also added to the payload. The packet is sent to the border router at `G`.
#. The border router at `G` receives the COLIBRI packet with ``R=1,C=1``,
   and forwards it to the next border router, at `F`.
#. The border router at `F` receives the packet. It checks whether the MAC
   is valid and drops the packet if not. If the MAC is
   valid (:math:`\text{MAC}_F^{C=1}` is independent of the ``R`` flag),
   the border router delivers it to the local COLIBRI service.
#. The COLIBRI service at `F` now add its own HopField and
   the two MACs :math:`\text{MAC}_F^{C=1}` and :math:`\sigma_F`,
   the latter encrypted with :math:`DRKey K_{F \to A}`.
   It then sends it to the border router.
#. The process continues until the packet reaches the COLIBRI service at `A`,
   where the HopFields inside are decrypted and stored so that COLIBRI
   traffic originating for this reservation can be correctly stamped with the
   appropriate MAC value.

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
   values for the reservation. It adds its HopField and the two MACs and
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
#. Otherwise a response will arrive before the timeout. If it is a failure,
   it gets reported in the logs. A new attempt of a setup is triggered.
#. If the response is successful, there will be a set of MACs in the
   the response, only for ``C=1`` (segment reservations are always
   ``C=1,S=1``). These MACs are stored alongside with the HopFields in the DB
   for this reservation, and the setup finishes.

Renew a Segment Reservation
***************************
#. The service triggers the renewal of the existing segment reservations
   with constant frequency.
#. The store in the COLIBRI service retrieves each one of the reservations
   that originate in this AS.
#. Per reservation retrieved, the store adds a new index to it and
   pushes it forward, with the same dynamics as in
   `Setup a Segment Reservation`_.

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

Handle a Renewal Request
************************
The renewal request handler is the same as the `handle a setup request`_.
The renewal is initiated differently (by adding a new index to an existing
reservation), but handled the same way.

Handle a Setup Response
***********************
#. If the response is a failure, it gets reported in the logs.
#. If the response is successful, the store saves the reservation as final.
   It also adds the HopField and its MAC for ``C=1`` to the response.
#. The store sends the response back in the direction it was already traveling
   (possibly with ``R=1`` unless this is a down-segment reservation).
#. If this AS is the first one in the reservation path (aka
   *reservation initiator*), the store also starts
   an index confirmation request.

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
#. The store pushes forward the setup request, successful or otherwise.

Handle an E2E Setup Response
****************************
#. The COLIBRI service receives a response traveling in the opposite direction
   as the request.
#. This COLIBRI service computes the maximum bandwidth it would be willing
   to grant, and adds this information to the response.
#. If the response was and still is successful after its own admission,
   the service adds its HopField and two sets of MACs to the response (the
   two sets are for ``C=0`` and ``C=1``).
#. The response is sent along its way.
#. If this was the COLIBRI service at the *reservation initiator* AS, the
   COLIBRI service decrypts the ``C=0`` MACs and sends them to the
   *stamping service* (the service in charge of computing the per packet MACs
   or *HVFs*) if the response was successful, and informs in any case of
   the result to the originating end-host of the reservation.

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
