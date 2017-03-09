@0xf85d2602085656cc;

using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct ScmpAuthRemoteReq {
    isdas @0 :UInt32;
    timestamp @1 :UInt32;
    signature @2 :Data;
    chain @3 :Data;
}

struct ScmpAuthRemoteRep {
    isdas @0 :UInt32;
    timestamp @1 :UInt32;
    cipher @2 :Data;
    signature @3 :Data;
    chain @4 :Data;
}

struct ScmpAuthLocalReq {
    isdas @0 :UInt32;
}

struct ScmpAuthLocalRep {
    isdas @0 :UInt32;
    cipher @1 :Data;
}

struct SCMPAuthMgmt {
    union {
        unset @0 :Void;
        scmpAuthRemoteReq @1 :ScmpAuthRemoteReq;
        scmpAuthRemoteRep @2 :ScmpAuthRemoteRep;
        scmpAuthLocalReq @3 :ScmpAuthLocalReq;
        scmpAuthLocalRep @4 :ScmpAuthLocalRep;
    }
}
