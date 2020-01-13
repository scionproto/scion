@0x93f5d82ab0601d9b;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");


struct ColibriExternalPkt {
    rpkt @0 :Data; # contains the raw packet
}

struct ColibriInstruct {
    id @0 :Data;
    expTime @1 :UInt64;
}

struct ColibriSegmentReq {
    startIA @0 :UInt64;
    endIA @1 :UInt64;
    segID @2 :Data;
    pathType @3 :UInt8;
}

struct ColibriSegmentRecs {
    entries @0 :List(ColibriBlockMeta);
}

struct ColibriSegmentRep {
    req @0 :ColibriSegmentReq;
    recs @1 :ColibriSegmentRecs;
}

struct ColibriSegmentRegRep {
    ack @0 :List(UInt16);
}

struct ColibriBlockMeta {
    id @0 :Data;
    block @1 :Data;
    creation @2 :UInt32;
    interfaces @3 :Data;
    signature @4 :Data;
    whiteList @5 :Data;
    mtu @6 :UInt16;
}


struct ColibriMgmt {
    union {
        unset @0 :Void;
        colibriExternalPkt @1 :ColibriExternalPkt;
        colibriInstruct @2 :ColibriInstruct;
        colibriSegmentReq @3 :ColibriSegmentReq;
        colibriSegmentRep @4 :ColibriSegmentRep;
        colibriSegmentReg @5 :ColibriSegmentRecs;
        colibriSegmentRegRep @6 :ColibriSegmentRegRep;
        colibriE2EReq @7 :ColibriExternalPkt;
        colibriE2ERep @8 :ColibriExternalPkt;
    }
}
