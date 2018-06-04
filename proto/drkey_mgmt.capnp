@0xf85d2602085656c1;

using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct DRKeyReq {
    isdas @0 :UInt64;      # Src ISD-AS of the requested DRKey
    valTime @1 :UInt64;    # Point in time where requested DRKey is valid
    certVer @2 :UInt32;    # Version cert used to sign
}

struct DRKeyRep {
    isdas @0 :UInt64;      # Src ISD-AS of the DRKey
    expTime @1 :UInt64;    # Expiration time of the DRKey
    cipher @2 :Data;       # Encrypted DRKey
    certVerSrc @3 :UInt32; # Version of cert used to sign
    certVerDst @4 :UInt32; # Version of cert of public key used to encrypt
}

struct DRKeyMgmt {
    union {
        unset @0 :Void;
        drkeyReq @1 :DRKeyReq;
        drkeyRep @2 :DRKeyRep;
    }
}
