@0xfb8053d9fb34b837;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

using Sign = import "sign.capnp";
using Sibra = import "sibra.capnp";
using Exts = import "asm_exts.capnp";

struct PathSegment {
    sdata @0 :Data; # Raw PathSegmentSignedData
    # asEntries[n].blob is a raw ASEntry. asEntries[n].sign is over signed + asEntries[:n]
    asEntries @1 :List(Sign.SignedBlob);
}

# Contains all top-level signed data for PathSegment
struct PathSegmentSignedData {
    infoF @0 :Data; # Raw InfoField
    timestamp @1 :UInt32; # Timestamp in seconds since epoch.
    segID @2 :UInt16;
}

struct ASEntry {
    isdas @0 :UInt64;  # Local ISD-AS
    trcVer @1 :UInt64;
    certVer @2 :UInt64;
    ifIDSize @3 :UInt8;  # Number of bits used for interface IDs in this AS.
    hops @4 :List(HopEntry);
    mtu @5 :UInt16;  # Internal AS MTU
    exts :group {
        routingPolicy @6 :Exts.RoutingPolicyExt;
        sibra @7 :Sibra.SibraPCBExt;
        hiddenPathSeg @8 :Exts.HiddenPathSegExtn;
        staticInfo @9 :Exts.StaticInfoExtn;
    }
}

struct HopEntry {
    inIA        @0 :UInt64;  # Ingress (incl peer) ISD-AS
    remoteInIF  @1 :UInt64;  # Interface ID on far end of ingress link
    inMTU       @2 :UInt16;  # Ingress Link MTU
    outIA       @3 :UInt64;  # Downstream ISD-AS
    remoteOutIF @4 :UInt64;  # Interface ID on far end of egress link
    hopF        @5 :Data;    # Raw HopField (deprecated)
    hopField :group {
        expTime     @6 :UInt8;   # Relative expiry time.
        consIngress @7 :UInt16;  # Interface ID of the ingress link.
        consEgress  @8 :UInt16;   # Interface ID of the egress link.
        mac         @9 :Data;
    }
}

# PathSegment Construction Beacon - used during path beaconing.
struct PCB {
    pathSeg @0 :PathSegment;
    ifID @1 :UInt64;  # Interface PCB came from
}

struct PathSegMeta {
    pathSeg @0 :PathSegment;
    type @1 :PathSegType;
}

enum PathSegType {
    unset @0;
    up @1;
    down @2;
    core @3;
}
