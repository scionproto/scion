@0xfb8053d9fb34b837;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

using Sibra = import "sibra.capnp";
using Exts = import "asm_exts.capnp";

struct PCBMarking {
    inIA @0 :UInt32;  # Ingress (incl peer) ISD-AS
    remoteInIF @1 :UInt64; # Interface ID on far end of ingress link
    inMTU @2 :UInt16;  # Ingress Link MTU
    outIA @3 :UInt32;  # Downstream ISD-AS
    remoteOutIF @4 :UInt64; # Interface ID on far end of egress link
    hof @5 :Data;
}

struct ASMarking {
    isdas @0 :UInt32;  # Local ISD-AS
    trcVer @1 :UInt32;
    certVer @2 :UInt32;
    ifIDSize @3 :UInt8;  # Number of bits used for interface IDs in this AS.
    pcbms @4 :List(PCBMarking);
    hashTreeRoot @5 :Data;
    sig @6 :Data;
    mtu @7 :UInt16;  # Internal MTU
    exts :group {
        routingPolicy @8 :Exts.RoutingPolicyExt;
    }
}

struct PathSegment {
    info @0 :Data;
    ifID @1 :UInt64;  # Interface PCB came from
    asms @2 :List(ASMarking);
    exts :group {
        sibra @3 :Sibra.SibraPCBExt;
    }
}

struct PathSegMeta {
    type @0 :UInt8;
    pcb @1 :PathSegment;
}
