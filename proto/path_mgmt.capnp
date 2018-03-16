@0x8fcd13516850d142;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

using PSeg = import "path_seg.capnp";
using IFState = import "if_state.capnp";
using RevInfo = import "rev_info.capnp";

struct SegReq {
    srcIA @0 :UInt64;
    dstIA @1 :UInt64;
    flags :group {
        sibra @2 :Bool;
        cacheOnly @3 :Bool;
    }

}

struct SegRecs {
    recs @0 :List(PSeg.PathSegMeta);
    revInfos @1 :List(RevInfo.RevInfo);
}

struct SegReply {
    req @0 :SegReq;
    recs @1 :SegRecs;
}

struct PathMgmt {
    union {
        unset @0 :Void;
        segReq @1 :SegReq;
        segReply @2 :SegReply;
        segReg @3 :SegRecs;
        segSync @4 :SegRecs;
        revInfo @5 :RevInfo.RevInfo;
        ifStateReq @6 :IFState.IFStateReq;
        ifStateInfos @7 :IFState.IFStateInfos;
    }
}
