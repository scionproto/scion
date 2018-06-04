@0xf85d2602085656c1;

using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct DRKeyLvl1Req {
    isdas @0 :UInt64;      # Src ISD-AS of the requested DRKey
<<<<<<< HEAD
    timestamp @1 :UInt32;  # Timestamp, seconds since Unix Epoch
    signature @2 :Data;    # Signature of (isdas, prefetch, timestamp)
    certVer @3 :UInt32;    # Version cert used to sign
    trcVer @4 :UInt32;     # Version of TRC, which signed cert
    flags :group {
        prefetch @5 :Bool; # Indicator request for current (false) or next (true) DRKey
    }

=======
    valTime @1 :UInt32;    # Point in time where requested DRKey is valid
>>>>>>> 621dc11... Mapping of FirstOrder Messages of Capnp to go/lib
}

struct DRKeyLvl1Rep {
    isdas @0 :UInt64;      # Src ISD-AS of the DRKey
<<<<<<< HEAD
    timestamp @1 :UInt32;  # Timestamp, seconds since Unix Epoch
    expTime @2 :UInt32;    # Expiration time of the DRKey, seconds since Unix Epoch
    cipher @3 :Data;       # Encrypted DRKey
    signature @4 :Data;    # Signature (isdas, cipher, timestamp, expTime)
    certVerSrc @5 :UInt32; # Version of cert used to sign
    certVerDst @6 :UInt32; # Version of cert of public key used to encrypt
    trcVer @7 :UInt32;     # Version of TRC, of signing cert
=======
    expTime @1 :UInt32;    # Expiration time of the DRKey
    cipher @2 :Data;       # Encrypted DRKey
    certVerSrc @3 :UInt64; # Version of cert used to sign
    certVerDst @4 :UInt64; # Version of cert of public key used to encrypt
>>>>>>> 621dc11... Mapping of FirstOrder Messages of Capnp to go/lib
}

struct DRKeyMgmt {
    union {
        unset @0 :Void;
        drkeyLvl1Req @1 :DRKeyLvl1Req;
        drkeyLvl1Rep @2 :DRKeyLvl1Rep;
    }
}
