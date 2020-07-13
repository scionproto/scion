@0x8fcd13516850d142;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

using PSeg = import "path_seg.capnp";
using IFState = import "if_state.capnp";
using Sign = import "sign.capnp";

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
    sRevInfos @1 :List(Sign.SignedBlob);
}

struct SegReply {
    req @0 :SegReq;
    recs @1 :SegRecs;
}

struct SegIds {
    segId @0 :Data;
    fullId @1 :Data;
}

struct HPGroupId {
    ownerAS @0 :UInt64;
    groupId @1 :UInt16;
}

struct HPSegReq {
    dstIA @0 :UInt64;
    groupIds @1 :List(HPGroupId);
}

struct HPSegRecs {
    groupId @0 :HPGroupId;
    recs @1 :List(PSeg.PathSegMeta);
    err @2 :Text;
}

struct HPSegReply {
    recs @0 :List(HPSegRecs);
}

struct HPCfg {
    groupId @0 :HPGroupId;
    version @1 :UInt32;
    ownerISD @2 :UInt16;
    writers @3 :List(UInt64);
    readers @4 :List(UInt64);
    registries @5 :List(UInt64);
}

struct HPCfgReq {
    changedSince @0 :UInt32;
}

struct HPCfgReply {
    cfgs @0 :List(HPCfg);
}

struct PathMgmt {
    union {
        unset @0 :Void;
        segReq @1 :SegReq;
        segReply @2 :SegReply;
        segReg @3 :SegRecs;
        sRevInfo @4 :Sign.SignedBlob;
        ifStateReq @5 :IFState.IFStateReq;
        ifStateInfos @6 :IFState.IFStateInfos;
        hpSegReq @7 :HPSegReq;
        hpSegReply @8 :HPSegReply;
        hpSegReg @9 :HPSegRecs;
        hpCfgReq @10 :HPCfgReq;
        hpCfgReply @11 :HPCfgReply;
    }
}
