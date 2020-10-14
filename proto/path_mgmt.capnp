@0x8fcd13516850d142;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

using PSeg = import "path_seg.capnp";
using Sign = import "sign.capnp";

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
        sRevInfo @1 :Sign.SignedBlob;
        hpSegReq @2 :HPSegReq;
        hpSegReply @3 :HPSegReply;
        hpSegReg @4 :HPSegRecs;
        hpCfgReq @5 :HPCfgReq;
        hpCfgReply @6 :HPCfgReply;
    }
}
