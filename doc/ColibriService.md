# COLIBRI Service Design

This document specifies the design of the COLIBRI service. It aims for correctness not completeness, and some parts of the design are deliberately not yet specified.

This document will be reviewed and amended when necessary as the implementation of the COLIBRI service matures.


## Overview

The COLIBRI Service (*COS*) manages the reservation process of the COLIBRI QoS subsystem in SCION. It handles both the segment and end to end reservations (aka steady and ephemeral reservations).

The border router is also modified so it understands COLIBRI type packets in the data plane.

**This document doesn't include the border router design and implementation changes yet.**


## Design

The COS is structured similarly to other existing Go infrastructure services. It reuses the following:

* [go/lib/env](../go/lib/env): Is used for configuration and setup of the service.
* [go/lib/infra/modules/trust](../go/lib/infra/modules/trust): Is used for crypto material.
* [go/lib/infra](../go/lib/infra): Is used for the messenger to send and receive messages.
* [go/lib/periodic](../go/lib/periodic): Is used for periodic tasks.

The COS is differentiated into these parts:

* **configuration** specifying admission and reservation parameters for this AS,
* **handlers** to handle incoming reservation requests (creation, tear down, etc.),
* **periodic tasks** for segment reservation creation and renewal,
* **reservation storage** for partial and committed reservations.

![COS parts overview](fig/colibri_srv/COS.png).

(which components do what, no UML)
(pretty figures with colors, group the classes per functionallity: handler, periodic task, etc)


## Interfaces

(interfaces of the main classes)

The Reservation Store in the COS keeps track of the reservations created and accepted in this AS, both segment and E2E.
The store provides the following interface:

```go
type ReservationStore {
    // TODO(juagargi): two segment reservations can differ only in their path;
    // this means that the path is part of the unique fields. pathAsIndex_t is some kind of ID for a path.

    GetSegmentReservations(ctx context.Context, validTime time.Time, path pathAsIndex_t) ([]SegmentReservation, error)
    GetSegmentReservation(ctx context.Context, token ReservationToken) (SegmentReservation, error)
    InsertSegmentReservation(ctx context.Context, resv SegmentReservation) error
    DeleteSegmentReservation(ctx context.Context, token ReservationToken) error

    // GetE2EReservationCount will return the number of existing end to end reservations
    // that are using the segment reservation specified by the token. If hostID is not empty, it will
    // check if there already exists an E2E reservation for that host with this token.
    GetE2EReservationCount(ctx context.Context, validTime time.Time, segmentReservationToken ReservationToken, host HostID) (int, error)
    InsertE2EReservation(ctx context.Context, resv E2EResevation) error
    // TODO(juagargi) other functions pending ...
}
```


## Class Diagrams

(just the main classes, arity and relationship)
(data relationships seem simple enough that we can probably skip them)


## Sequence Diagrams

(just one or two UML sequence diagrams to validate)

TODO(juagargi) for now a simple list, move to diagram

1. The service triggers the creation of a new segment reservation periodically (also at boot time).
1. The store contained in the service is queried to admit the segment reservation.
1. The store decides the admission for the reservation (how much bandwidth)
1. The store saves an intermediate reservation entry in the DB
1. The store requests the next AS in the reservation path for the decided bandwidth.
1. The COLIBRI service in the next AS in the path receives the request.
1. That service handles the request. This AS might be the last one in the path. If it is not, it repeats the previous steps.
1. When the AS is the last one, the COLIBRI service via its store saves the reservation as final and notifies the previous AS in the path of the transaction.
1. The COLIBRI service in the previous AS receives the notification (request to commit to this reservation).
1. That service, via its store, saves the reservation as final and notifies the previous AS again. These steps are repeated until the first AS is reached.
1. The COLIBRI service in the first AS is reached.
1. That service, via its store, also writes down the reservation as final.




## Detail per Class

(explain with better detail each one of the main classes)


