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

struct AllocationBead {
    allocBW @0 :UInt8;
    maxBW @1 :UInt8;
}

# All segment requests identify a single index of a segment reservation.
# Even for setup it is useful to avoid creating a different index down the reservation path, as
# the requester AS can cleanup an index and without waiting for success start already a new setup.
struct SegmentBase {
    id @0 :SegmentReservationID;
    index @1 :UInt8;
}

struct E2EBase {
    id @0 :E2EReservationID;
    index @1 :UInt8;
}

# Request to setup a segment reservation.
struct SegmentSetupReqData {
    base @0 :SegmentBase;
    minBW @1 :UInt8;
    maxBW @2 :UInt8;
    splitCls @3 :UInt8;
    startProps @4 :PathEndProps;
    endProps @5 :PathEndProps;
    infoField @6 :Data; # ExpirationTick, Index, BWCls, RLC, and PathType; expected 8 bytes
    allocationTrail @7 :List(AllocationBead);  # updated on each AS along the path
}

# Response to a segment setup request.
struct SegmentSetupResData {
    base @0 :SegmentBase;
    union{
        unset @1 :Void;
        failure @2 :SegmentSetupReqData; # sent along the path in the opposite direction in case of failure
        token   @3 :Data;                # if successful
    }
}

# Telescoped segment reservations. Their response is identical to a non telescoped setup.
struct SegmentTelesSetupData {
    setup @0 :SegmentSetupReqData;
    baseID @1 :SegmentReservationID;
}

# Request to tear down a segment reservation.
struct SegmentTeardownReqData {
    base @0 :SegmentBase;
}

# Response to a tear down request.
struct SegmentTeardownResData {
    base @0 :SegmentBase;
    errorCode @1 :UInt8;    # only relevant if the response indicates failure
}

# Segment reservation index confirmation request.
struct SegmentIndexConfirmationData {
    base @0 :SegmentBase;
    state @1 :ReservationIndexState;
}

# Response to a index confirmation request.
struct SegmentIndexConfirmationResData {
    base @0 :SegmentBase;
    errorCode @1: UInt8;  # only relevant if the response indicates failure
}

# Removes a pending segment reservation.
struct SegmentCleanupData {
    base @0 :SegmentBase;
}

struct SegmentCleanupResData {
    base @0 :SegmentBase;
    errorCode @1: UInt8;  # only relevant if the response indicates failure
}

# TODO(juagargi) the e2e setup request travels forward only if successful, change the type down here:

# Setup an E2E reservation. Sent in a hop by hop colibri extension through
# a stitched segment reservation. Every AS adds to the allocation trail 
# the minimum between what it is willing to grant and the value in the request.
# The request is accepted if all the ASes granted the requested value and no less.
# The request travels the full path up to the destination endhost, and only then
# it is returned to the requester endhost.
struct E2ESetupReqData {
    base @0 :E2EBase;
    segmentRsvs @1 :List(SegmentReservationID);
    segmentRsvASCount @2 :List(UInt8);  # how many ASes in each segment reservation
    requestedBW @3 :UInt8;
    allocationTrail @4 :List(UInt8);
    union {
        unset @5 :Void;
        success :group {
            token @6 :Data;
        }
        failure :group {
            errorCode @7 :UInt8;
        }
    }
}

# Response to an E2E setup. Sent in a hop by hop colibry extension, in the reverse path.
struct E2ESetupResData {
    base @0 :E2EBase;
    union {
        unset @1 :Void;
        success :group {
            token @2 :Data;
        }
        failure :group {
            errorCode @3 :UInt8;
            allocationTrail @4 :List(UInt8);     # max bandwidths granted by all the ASes. See E2ESetupReqData
        }
    }
}

# Removes a partially setup e2e index.
struct E2ECleanupData {
    base @0 :E2EBase;
}

struct E2ECleanupResData {
    base @0 :E2EBase;
    errorCode @1 :UInt8;
}

# All possible requests between ASes. A requests travels to the next AS.
struct Request {
    union {
        unset @0 :Void;
        segmentSetup @1 :SegmentSetupReqData;
        segmentRenewal @2 :SegmentSetupReqData;
        segmentTelesSetup @3 :SegmentTelesSetupData;
        segmentTelesRenewal @4 :SegmentTelesSetupData;
        segmentTeardown @5 :SegmentTeardownReqData;
        segmentIndexConfirmation @6 :SegmentIndexConfirmationData;
        segmentCleanup @7 :SegmentCleanupData;
        e2eSetup @8 :E2ESetupReqData;
        e2eRenewal @9 :E2ESetupReqData;
        e2eCleanup @10 :E2ECleanupData;
    }
}
# A Response can be negative (not accepted). In that case, failedHop indicates which hop along the path failed it.
# Responses travel in the reverse direction as requests, whether successful or not.
struct Response {
    union {
        unset @0 :Void;
        segmentSetup @1 :SegmentSetupResData;   # also for teles. setup
        segmentRenewal @2 :SegmentSetupResData; # also for teles. renewal
        segmentTeardown @3 :SegmentTeardownResData;
        segmentIndexConfirmation @4 :SegmentIndexConfirmationResData;
        segmentCleanup @5 :SegmentCleanupResData;
        e2eSetup @6 :E2ESetupResData;
        e2eRenewal @7 :E2ESetupResData;
        e2eCleanup @8 :E2ECleanupResData;
    }
    accepted @9 :Bool;
    failedHop @10 :UInt8;    # which hop failed the request
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
    # TODO(juagargi) DRKey authenticators
}
