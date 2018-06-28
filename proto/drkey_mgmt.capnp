@0xf85d2602085656c1;

using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct DRKeyReq {
    isdas @0 :UInt64;      # Src ISD-AS of the requested DRKey
    timestamp @1 :UInt32;  # Timestamp, seconds since Unix Epoch
    signature @2 :Data;    # Signature of (isdas, prefetch, timestamp)
    certVer @3 :UInt32;    # Version cert used to sign
    trcVer @4 :UInt32;     # Version of TRC, which signed cert
    flags :group {
        prefetch @5 :Bool; # Indicator request for current (false) or next (true) DRKey
    }

}

struct DRKeyRep {
    isdas @0 :UInt64;      # Src ISD-AS of the DRKey
    timestamp @1 :UInt32;  # Timestamp, seconds since Unix Epoch
    expTime @2 :UInt32;    # Expiration time of the DRKey, seconds since Unix Epoch
    cipher @3 :Data;       # Encrypted DRKey
    signature @4 :Data;    # Signature (isdas, cipher, timestamp, expTime)
    certVerSrc @5 :UInt32; # Version of cert used to sign
    certVerDst @6 :UInt32; # Version of cert of public key used to encrypt
    trcVer @7 :UInt32;     # Version of TRC, of signing cert
}

struct DRKeyMgmt {
    union {
        unset @0 :Void;
        drkeyReq @1 :DRKeyReq;
        drkeyRep @2 :DRKeyRep;
    }
}
