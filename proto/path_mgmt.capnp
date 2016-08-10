@0x8fcd13516850d142;

using PCB = import "pcb.capnp";
using IFState = import "if_state.capnp";
using RevInfo = import "rev_info.capnp";

struct SegReq {
    srcIA @0 :Text;
    dstIA @1 :Text;
    flags :group {
        sibra @2 :Bool;
    }
}

struct SegRecs {
    recs @0 :List(PCB.PathSegMeta);
}

struct PathMgmt {
    union {
        unset @0 :Void;
        segReq @1 :SegReq;
        segReply @2 :SegRecs;
        segReg @3 :SegRecs;
        segSync @4 :SegRecs;
        revInfo @5 :RevInfo.RevInfo;
        ifStateReq @6 :IFState.Req;
        ifStateInfos @7 :IFState.Infos;
    }
}
