@0xf85d2602085656c1;

using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct DRKeyReq {
    prefetch @0 :Bool;
    isdas @1 :UInt32;
    timestamp @2 :UInt64;
    signature @3 :Data;
    certVer @4 :UInt32;
    trcVer @5 :UInt32;
}

struct DRKeyRep {
    isdas @0 :UInt32;
    timestamp @1 :UInt64;
    expTime @2 :UInt64;
    cipher @3 :Data;
    signature @4 :Data;
    certVerSrc @5 :UInt32;
    certVerDst @6 :UInt32;
    trcVerSrc @7 :UInt32;
}

struct DRKeyMgmt {
    union {
        unset @0 :Void;
        drkeyReq @1 :DRKeyReq;
        drkeyRep @2 :DRKeyRep;
    }
}
