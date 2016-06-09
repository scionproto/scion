@0xfb8053d9fb34b837;

using RevInfo = import "rev_info.capnp";
using Sibra = import "sibra.capnp";

struct PCBMarking {
    inIA @0 :Text;  # Ingress (incl peer) ISD-AS
    inIF @1 :UInt64; # Interface ID on far end of ingress link
    inMTU @2 :UInt16;  # Ingress Link MTU
    outIA @3 :Text;  # Downstream ISD-AS
    outIF @4 :UInt64; # Interface ID on far end of egress link
    hof @5 :Data;
    igRevToken @6 :Data;
}

struct ASMarking {
    isdas @0 :Text;  # Local ISD-AS
    trcVer @1 :UInt32;
    certVer @2 :UInt32;
    ifIDSize @3 :UInt8;  # Number of bits used for interface IDs in this AS.
    pcbms @4 :List(PCBMarking);
    egRevToken @5 :Data;
    exts :group {
        revInfos @6 :List(RevInfo.RevInfo);
    }
    sig @7 :Data;
    mtu @8 :UInt16;  # Internal MTU
    chain @9 :Data;  # FIXME(kormat): to be removed when propagation is over TCP.
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
