@0xe8550b6088706947;

using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

using PathMgmt = import "path_mgmt.capnp";
using HPCfg = import "hp_cfg.capnp";

struct HPCfgReq {
    hpCfgIds @0 :List(HPCfg.HPCfgId);
}

struct HPCfgRecs {
    hpCfgs @0 :List(HPCfg.HPCfg);
}

struct HPMgmt {
    timestamp @0 :UInt64;
    signature @1 :Data;
    union {
        hpCfgReq @2 :HPCfgReq;
        hpCfgReply @3 :HPCfgRecs;
        hpCfgReg @4 :HPCfgRecs;
        hpSegReq @5 :PathMgmt.SegReq;
        hpSegReply @6 :PathMgmt.SegRecs;
        hpSegReg @7 :PathMgmt.SegRecs;
    }
}
