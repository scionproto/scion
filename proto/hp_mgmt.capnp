@0xe8550b6088706947;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

using PathMgmt = import "path_mgmt.capnp";
using HPCfg = import "hp_cfg.capnp";

struct HPCfgReq {
    hpCfgIds @0 :List(HPCfg.HPCfgId);
}

struct HPCfgRecs {
    hpCfgs @0 :List(HPCfg.HPCfg);
}

struct HPMgmt {
    union {
        hpCfgReq @0 :HPCfgReq;
        hpCfgReply @1 :HPCfgRecs;
        hpCfgReg @2 :HPCfgRecs;
        hpSegReq @3 :PathMgmt.SegReq;
        hpSegReply @4 :PathMgmt.SegReply;
        hpSegReg @5 :PathMgmt.SegRecs;
    }
}
