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
    linktype @2 :LinkTypeInfo;
    bandwidth @3 :BandwidthInfo;
    internalHops @4 :InternalHopsInfo;
    note @5 :Text;


    struct LatencyInfo {
        childLatencies @0 :List(ChildLatency);
        peeringLatencies @1 :List(PeerLatency);
        egressLatency @2 :UInt16;
        ingressToEgressLatency @3 :UInt16;

        struct ChildLatency {
            intra @0 :UInt16;
            ifID @1 :UInt16;
        }

        struct PeerLatency {
            intra @0 :UInt16;
            inter @1 :UInt16;
            ifID @2 :UInt16;
        }
    }

    struct BandwidthInfo {
        bandwidths @0 :List(InterfaceBandwidth);
        egressBW @1 :UInt32;
        ingressToEgressBW @2 :UInt32;

        struct InterfaceBandwidth {
            bw @0 :UInt32;
            ifID @1 :UInt16;
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
        peeringLinks @0 :List(InterfaceLinkType);
        egressLinkType @1 :LinkType;

        enum LinkType{
            direct @0;
            multiHop @1;
            openNet @2;
        }

        struct InterfaceLinkType {
            ifID @0 :UInt16;
            linkType @1 :LinkType;
        }
    }

    struct InternalHopsInfo {
        interfaceHops @0 :List(InterfaceHops);
        inToOutHops @1 :UInt8;

        struct InterfaceHops {
            hops @0 :UInt8;
            ifID @1 :UInt16;
        }
    }
}
