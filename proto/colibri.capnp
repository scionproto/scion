@0xa3bf9fed859570f0;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");


struct SegmentReservationID {
    asid @0 :Data;      # 6 bytes
    suffix @1 :Data;    # 4 bytes long
}

struct E2EReservationID {
    asid @0 :Data;      # 6 bytes
    suffix @1 :Data;    # 16 bytes long
}

enum ReservationIndexState {
    pending @0;
    active @1;
}

struct PathEndProps {
    local @0 :Bool;     # allow delivery at the end AS
    transfer @1 :Bool;  # allow stitching with another reservation
}

struct AllocationBeads {
    allocBW @0 :UInt8;
    maxBW @1 :UInt8;
}

# Request to setup a segment reservation.
# Setups travel inside a hop by hop colibri extension and thus have a SegmentReservationID and index externally.
struct SegmentSetupReqData {
    minBW @0 :UInt8;
    maxBW @1 :UInt8;
    splitCls @2 :UInt8;
    startProps @3 :PathEndProps;
    endProps @4 :PathEndProps;
    allocationTrail @5 :List(AllocationBeads);  # updated on each AS along the path
}

# Response to a segment setup request.
# They travel inside a hop by hop colibri extension.
struct SegmentSetupResData {
    union{
        failure @0 :SegmentSetupReqData; # sent along the path in the opposite direction in case of failure
        token   @1 :Data;                # if successful
    }
}

# Request to renew an existing segment reservation.
# They travel inside a hop by hop colibri extension (SegmentReservationID and index available externally).
struct SegmentRenewalData {
    minBW @0 :UInt8;
    maxBW @1 :UInt8;
    allocationTrail @2 :List(AllocationBeads);
}

# Telescoped segment reservations. Their response is identical to a non telescoped setup.
# They travel in a hop by hop colibri extension.
struct SegmentTelesSetupData {
    setup @0 :SegmentSetupReqData;
    baseID @1 :SegmentReservationID;
}

# Request to tear down a segment reservation.
struct SegmentTeardownReqData {}   # empty (SegmentReservationID and index from hop by hop extension)

# Response to a tear down request.
struct SegmentTeardownResData {
    errorCode @0 :UInt8;    # only relevant if the response indicates failure
}

# Segment reservation index confirmation request.
# They travel inside hop by hop colibri extension.
struct SegmentIndexConfirmationData {
    index @0 :UInt8;
    state @1 :ReservationIndexState;
}

# Removes a pending segment reservation.
# These messages travel as payload of a hop by hop colibri extension packet.
struct SegmentCleanupData {
    id @0 :SegmentReservationID;
    index @1 :UInt8;
}

# Setup an E2E reservation. Sent in a hop by hop colibri extension through a stitched segment reservation.
struct E2ESetupReqData {
    reservationID @0 :E2EReservationID;     # 16 byte e2e reservation ID
    token @1 :Data;
}

# Response to a e2e setup request.
struct E2ESetupResData {
    reservationID @0 :E2EReservationID;     # 16 byte e2e reservation ID
    errorCode @1 :UInt8;
    maxBWs @2 :List(UInt8);     # max bandwidths granted by the ASes along the path, until failure
}

# A renewal consists of the same fields as a setup.
struct E2ERenewalData {
    setup @0 :E2ESetupReqData;
}

# The reservation ID is needed because this request can be for a previously failed setup.
struct E2ECleanupData {
    reservationID @0 :E2EReservationID;
}

# All possible requests between ASes.
struct Request {
    union {
        unset @0 :Void;
        segmentSetup @1 :SegmentSetupReqData;
        segmentRenewal @2 :SegmentRenewalData;
        segmentTelesSetup @3 :SegmentTelesSetupData;
        segmentTelesRenewal @4 :SegmentRenewalData;
        segmentTeardown @5 :SegmentTeardownReqData;
        segmentIndexConfirmation @6 :SegmentIndexConfirmationData;
        segmentCleanup @7 :SegmentCleanupData;
        e2eSetup @8 :E2ESetupReqData;
        e2eRenewal @9 :E2ERenewalData;
        e2eCleanup @10 :E2ECleanupData;
    }
}
# A Response can be negative (not accepted). In that case, failedHop indicates which hop along the path failed it.
struct Response {
    union {
        unset @0 :Void;
        segmentSetup @1 :SegmentSetupResData;
        segmentRenewal @2 :SegmentSetupResData;
        segmentTelesSetup @3 :SegmentSetupResData;  # same response type as a normal setup
        segmentTelesRenewal @4 :SegmentSetupResData;
        segmentTeardown @5 :SegmentTeardownResData;
        segmentIndexConfirmation @6 :SegmentIndexConfirmationData;
        segmentCleanup @7 :SegmentCleanupData;
        e2eSetup @8 :E2ESetupResData;
        e2eRenewal @9 :E2ESetupResData; # same response type as a setup
        e2eCleanup @10 :E2ECleanupData;
    }
    accepted @11 :Bool;
    failedHop @12 :UInt8;    # which hop failed the request
}

# This travels inside a payload of a hop by hop colibri extension packet.
# It will contain either a Request or a Response. Responses are often identical to their Request counter parts.
struct ColibriRequestPayload {
    timestamp @0 :UInt32;
    union {
        unset @1 :Void;
        request @2 :Request;
        response @3 :Response;
    }
    # TODO(juagargi) authenticators
}
