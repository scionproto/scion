@0xe6c88f91b6a1209e;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct RoutingPolicyExt{
    set @0 :Bool;   # Is the extension present? Every extension must include this field.
    polType @1 :UInt8;  # The policy type
    ifID @2 :UInt64;
    isdases @3 :List(UInt64);
}

struct ISDAnnouncementExt{
    set @0 :Bool;   # TODO(Sezer): Implement announcement extension
}

struct HiddenPathSegExtn{
    set @0 :Bool;
}

struct StaticInfoExtn {
    latency @0 :LatencyInfo;
    geo @1 :GeoInfo;
    linktype @2 :LinktypeInfo;
    bandwidth @3 :BandwidthInfo;
    internalHops @4 :InternalHopsInfo;
    note @5 :Text;
   

    struct LatencyInfo {
        childLatencies @0 :List(LCPair);
        peeringLatencies @1 :List(LPTriplet);
        egressLatency @2 :UInt16;
        ingressToEgressLatency @3 :UInt16;

        struct LCPair {
            intraDelay @0 :UInt16;
            interface @1 :UInt16;
        }

        struct LPTriplet {
            intraDelay @0 :UInt16;
            interDelay @1 :UInt16;
            interface @2 :UInt16;
        }
    }

    struct BandwidthInfo {
        bandwidthPairs @0 :List(BWPair);
        egressBW @1 :UInt32;
        ingressToEgressBW @2 :UInt32;

        struct BWPair {
            BW @0 :UInt32;
            interface @1 :UInt16;
        }
    }

    struct GeoInfo {
        locations @0 :List(Location);

        struct Location {
            gpsData @0 :Coordinates;
            interfaces @1 :List(UInt16);

            struct Coordinates {
                latitude @0 :Float32;
                longitude @1 :Float32;
                address @2 :Data;
            }
        }
    }

    struct LinkTypeInfo {
        peeringLinks @0 :List(PeeringPair);
        egressLinkType @1 :LinkType;

        enum LinkType{
            direct @0;
            multiHop @1;
            openNet @2;
        }

        struct PeeringPair {
            interface @0 :UInt16;
            peeringLinkType @1 :LinkType;
        }
    }

    struct InternalHopsInfo {
        hopPairs @0 :List(HopPair);
        inToOutHops @1 :UInt8;

        struct HopPair {
            Hops @0 :UInt8;
            interface @1 :UInt16;
        }
    }
}
