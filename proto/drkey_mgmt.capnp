@0xf85d2602085656c1;

using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct DRKeyReq {
    isdas @0 :UInt32;      # Src ISD-AS of the requested DRKey
    timestamp @1 :UInt64;  # Timestamp
    signature @2 :Data;    # Signature of (isdas, prefetch, timestamp)
    certVer @3 :UInt32;    # Version cert used to sign
    trcVer @4 :UInt32;     # Version of TRC, which signed cert
    flags :group {
        prefetch @5 :Bool; # Indicator request for current (false) or next (true) DRKey
    }

}

struct DRKeyRep {
    isdas @0 :UInt32;      # Src ISD-AS of the DRKey
    timestamp @1 :UInt64;  # Timestamp
    expTime @2 :UInt64;    # Expiration time of the DRKey
    cipher @3 :Data;       # Encrypted DRKey
    signature @4 :Data;    # Signature (isdas, cipher, timestamp, expTime)
    certVerSrc @5 :UInt32; # Version of cert used to sign
    certVerDst @6 :UInt32; # Version of cert of public key used to encrypt
    trcVer @7 :UInt32;     # Version of TRC, of signing cert
}

struct DRKeyHostHolder {
    type @0 :UInt8; # AddrType
    host @1 :Data;  # Host address
}

struct DRKeyProtocolReq {
    protocol @0 :UInt32;  # Protocol identifier
    reqID @1 :UInt64;     # Request identifier
    timestamp @2 :UInt64; # Timestamp
    reqType @3 :UInt8;    # Requested DRKeyProtoKeyType
    srcIA @4 :UInt32;     # Src ISD-AS of the requested DRKey
    dstIA @5 :UInt32;     # Dst ISD-AS of the requested DRKey
    addIA :union {        # Additional ISD-AS of the requested DRKey (optional)
        unset @6 :Void;
        ia @7 :UInt32;
    }
    srcHost :union {      # Src Host of the request DRKey (optional)
        unset @8 :Void;
        holder @9 :DRKeyHostHolder;
    }
    dstHost :union {      # Dst Host of the request DRKey (optional)
        unset @10 :Void;
        holder @11 :DRKeyHostHolder;
    }
    addHost :union {      # Additional Host of the request DRKey (optional)
        unset @12 :Void;
        holder @13 :DRKeyHostHolder;
    }
    misc :union {         # Additional information for DRKey derivation (optional)
        unset @14 :Void;
        opt @15 :MiscOPTReq;
    }
}

struct DRKeyProtocolRep {
    reqID @0 :UInt64;     # Request identifier
    timestamp @1 :UInt64; # Timestamp
    drkey @2 :Data;       # Derived DRKey
    expTime @3 :UInt64;   # Expiration time of DRKey
    misc :union {         # Additional information (optional)
        unset @4 :Void;
        opt @5 :MiscOPTRep;
    }
}

struct DRKeyMgmt {
    union {
        unset @0 :Void;
        drkeyReq @1 :DRKeyReq;
        drkeyRep @2 :DRKeyRep;
        drkeyProtocolReq @3 :DRKeyProtocolReq;
        drkeyProtocolRep @4 :DRKeyProtocolRep;
    }
}

struct MiscOPTReq {
    sessionID @0 :Data;    # Session id (16B)
    path @1 :List(UInt32); # List of ASes on the path.
}

struct MiscOPTRep {
    drkeys @0 :List(Data); # List of DRKeys for ASes on the path.
}
