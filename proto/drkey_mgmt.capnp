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

struct DRKeyHost {
    type @0 :UInt8; # AddrType
    host @1 :Data;  # Host address
}

struct DRKeyLvl2Req {
    protocol @0 :Data;    # Protocol identifier
    reqID @1 :UInt64;     # Request identifier
    timestamp @2 :UInt64; # Timestamp
    reqType @3 :UInt8;    # Requested DRKeyProtoKeyType
    srcIA @4 :UInt64;     # Src ISD-AS of the requested DRKey
    dstIA @5 :UInt64;     # Dst ISD-AS of the requested DRKey
    addIA :union {        # Additional ISD-AS of the requested DRKey (optional)
        unset @6 :Void;
        ia @7 :UInt64;
    }
    srcHost :union {      # Src Host of the request DRKey (optional)
        unset @8 :Void;
        host @9 :DRKeyHost;
    }
    dstHost :union {      # Dst Host of the request DRKey (optional)
        unset @10 :Void;
        host @11 :DRKeyHost;
    }
    addHost :union {      # Additional Host of the request DRKey (optional)
        unset @12 :Void;
        host @13 :DRKeyHost;
    }
    misc :union {         # Additional information for DRKey derivation (optional)
        unset @14 :Void;
    }
}

struct DRKeyLvl2Rep {
    reqID @0 :UInt64;     # Request identifier
    timestamp @1 :UInt64; # Timestamp
    drkey @2 :Data;       # Derived DRKey
    expTime @3 :UInt32;   # Expiration time of DRKey
    misc :union {         # Additional information (optional)
        unset @4 :Void;
    }
}

struct DRKeyMgmt {
    union {
        unset @0 :Void;
        drkeyLvl1Req @1 :DRKeyLvl1Req;
        drkeyLvl1Rep @2 :DRKeyLvl1Rep;
        drkeyLvl2Req @3 :DRKeyLvl2Req;
        drkeyLvl2Rep @4 :DRKeyLvl2Rep;
    }
}
