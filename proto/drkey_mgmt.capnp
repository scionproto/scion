@0xf85d2602085656c1;

using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct DRKeyReq {
    isdas @0 :UInt32; # src ISD-AS of the requested DRKey
    timestamp @1 :UInt64;
    signature @2 :Data;
    certVer @3 :UInt32;
    trcVer @4 :UInt32;
    prefetch @5 :Bool; # indicator request for current (false) or next (true) DRKey
}

struct DRKeyRep {
    isdas @0 :UInt32; # src ISD-AS of the DRKey
    timestamp @1 :UInt64;
    expTime @2 :UInt64; # expiration time of the DRKey
    cipher @3 :Data; # Encrypted DRKey
    signature @4 :Data;
    certVerSrc @5 :UInt32;
    certVerDst @6 :UInt32;
    trcVer @7 :UInt32;
}

struct DRKeyMgmt {
    union {
        unset @0 :Void;
        drkeyReq @1 :DRKeyReq;
        drkeyRep @2 :DRKeyRep;
    }
}
