@0xe6d9e9e231c09f51;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

using RevInfo = import "rev_info.capnp";

struct IFStateInfo {
    ifID @0 :UInt64;
    active @1 :Bool;
    revInfo @2 :RevInfo.RevInfo;
}

struct IFStateInfos {
    infos @0 :List(IFStateInfo);
}

struct IFStateReq {
    ifID @0 :UInt64;
}
