@0xf85d2602085656c1;

using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct DRKeyReq {
    prefetch @0 :Bool;
    isdas @1 :UInt32;
    timestamp @2 :UInt64;
    signature @3 :Data;
    chain @4 :Data;
}

struct DRKeyRep {
    prefetch @0 :Bool;
    isdas @1 :UInt32;
    timestamp @2 :UInt64;
    cipher @3 :Data;
    signature @4 :Data;
    chain @5 :Data;
}

struct DRKeyProtoReq {
    timestamp @0 :UInt64;
    cipher @1 :Data;
    signature @2 :Data;
}

struct DRKeyProtoRep {
    timestamp @0 :UInt64;
    cipher @1 :Data;
    signature @2 :Data;

}

struct DRKeyHostHolder {
    type @0 :UInt8;
    host @1 :Data;
}

struct DRKeyProtocolRequest {
    reqCode @0 :UInt8;
    srcIA @1 :Data;
    dstIA @2 :Data;
    addIA :union {
        unset @3 :Void;
        ia @4 :Data;
    }
    srcHost :union {
        unset @5 :Void;
        holder @6 :DRKeyHostHolder;
    }
    dstHost :union {
        unset @7 :Void;
        holder @8 :DRKeyHostHolder;
    }
    addHost :union {
        unset @9 :Void;
        holder @10 :DRKeyHostHolder;
    }
    protocol @11 :UInt32;
    reqID @12 :UInt64;
}

struct DRKeyProtocolReply {
    reqID @0 :UInt64;
    drkey @1 :Data;
    expTime @2 :UInt64;
}

struct DRKeyMgmt {
    union {
        unset @0 :Void;
        drkeyReq @1 :DRKeyReq;
        drkeyRep @2 :DRKeyRep;
        drkeyProtoReq @3 :DRKeyProtoReq;
        drkeyProtoRep @4 :DRKeyProtoRep;
    }
}
