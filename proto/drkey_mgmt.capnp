@0xf85d2602085656c1;

using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct DRKeyLvl1Req {
    isdas @0 :UInt64;      # Src ISD-AS of the requested DRKey
    valTime @1 :UInt32;    # Point in time where requested DRKey is valid
}

struct DRKeyLvl1Rep {
    isdas @0 :UInt64;      # Src ISD-AS of the DRKey
    expTime @1 :UInt32;    # Expiration time of the DRKey
    cipher @2 :Data;       # Encrypted DRKey
    certVerSrc @3 :UInt64; # Version of cert used to sign
    certVerDst @4 :UInt64; # Version of cert of public key used to encrypt
}

struct DRKeyMgmt {
    union {
        unset @0 :Void;
        drkeyLvl1Req @1 :DRKeyLvl1Req;
        drkeyLvl1Rep @2 :DRKeyLvl1Rep;
    }
}
