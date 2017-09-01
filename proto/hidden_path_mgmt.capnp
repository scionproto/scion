@0xe8550b6088706947;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

using PathMgmt = import "path_mgmt.capnp";

struct HPCfgId {
    masterIA @0 :Data;
    cfgId @1 :UInt64;
}

struct HPCfg {
    id @0 :HPCfgId;
    version @1: UInt64;
    hpIAs @2 :List(Data);
    writeIAs @3 :List(Data);
    readIAs @4 :List(Data);
}

struct CfgReq {
    hpCfgIds @0 :List(HPCfgId);
}

struct CfgRecs {
    hpCfgs @0 :List(HPCfg);
}

struct HPMsg {
    union {
        hpCfgReg @0 :CfgRecs;
        hpCfgReq @1 :CfgReq;
        hpCfgReply @2 :CfgRecs;
        segReg @3 :PathMgmt.SegRecs;
        segReq @4 :PathMgmt.SegReq;
        segReply @5 :PathMgmt.SegRecs;
    }
    timestamp @6 :UInt64;
    signature @7 :Data;
}
