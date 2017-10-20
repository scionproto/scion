@0x8fcd13516850d142;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

using PCB = import "pcb.capnp";
using IFState = import "if_state.capnp";
using RevInfo = import "rev_info.capnp";
using HPCfg = import "hp_cfg.capnp";

struct SegReq {
    srcIA @0 :UInt32;
    dstIA @1 :UInt32;
    flags :group {
        sibra @2 :Bool;
        cacheOnly @3 :Bool;
    }
    meta :group {
        hpCfgIds @4 :List(HPCfg.HPCfgId);
    }
}

struct SegRecs {
    recs @0 :List(PCB.PathSegMeta);
    meta :group {
        revInfos @1 :List(RevInfo.RevInfo);
        hpCfgIds @2 :List(HPCfg.HPCfgId);
    }

}

struct PathMgmt {
    union {
        unset @0 :Void;
        segReq @1 :SegReq;
        segReply @2 :SegRecs;
        segReg @3 :SegRecs;
        segSync @4 :SegRecs;
        revInfo @5 :RevInfo.RevInfo;
        ifStateReq @6 :IFState.IFStateReq;
        ifStateInfos @7 :IFState.IFStateInfos;
    }
}
