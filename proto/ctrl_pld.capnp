@0xdf42b02816bdc1bf;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

using Sign = import "sign.capnp";
using PSeg = import "path_seg.capnp";
using PathMgmt = import "path_mgmt.capnp";
using SIBRA = import "sibra.capnp";
using DRKeyMgmt = import "drkey_mgmt.capnp";
using SIG = import "sig.capnp";
using Ack = import "ack.capnp";

struct SignedCtrlPld {
    blob @0 :Data;  # Raw CtrlPld
    sign @1 :Sign.Sign;
}

struct CtrlPld {
    union {
        unset @0 :Void;
        pcb @1 :PSeg.PCB;
        pathMgmt @2 :PathMgmt.PathMgmt;
        sibra @3 :SIBRA.SibraPayload;
        drkeyMgmt @4 :DRKeyMgmt.DRKeyMgmt;
        sig @5 :SIG.SIGCtrl;
        ack @6 :Ack.Ack;
    }
    reqId @7 :UInt64;
    traceId @8 :Data;
}
