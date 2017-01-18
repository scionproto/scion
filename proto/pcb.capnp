@0xfb8053d9fb34b837;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

using RevInfo = import "rev_info.capnp";
using Sibra = import "sibra.capnp";

struct PCBMarking {
    inIA @0 :UInt32;  # Ingress (incl peer) ISD-AS
    inIF @1 :UInt64; # Interface ID on far end of ingress link
    inMTU @2 :UInt16;  # Ingress Link MTU
    outIA @3 :UInt32;  # Downstream ISD-AS
    outIF @4 :UInt64; # Interface ID on far end of egress link
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
    chain @8 :Data;  # FIXME(kormat): to be removed when propagation is over TCP.
}

struct PathSegment {
    info @0 :Data;
    ifID @1 :UInt64;  # Interface PCB came from
    asms @2 :List(ASMarking);
    exts :group {
        sibra @3 :Sibra.SibraPCBExt;
        revInfos @4 :List(RevInfo.RevInfo);
    }
}

struct PathSegMeta {
    type @0 :UInt8;
    pcb @1 :PathSegment;
}
