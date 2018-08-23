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
<<<<<<< HEAD

=======
>>>>>>> 15b7df5... Second level drkey message representation
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
