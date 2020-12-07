@0xdf42b02816bdc1bf;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

using Sign = import "sign.capnp";
using DRKeyMgmt = import "drkey_mgmt.capnp";

struct SignedCtrlPld {
    blob @0 :Data;  # Raw CtrlPld
    sign @1 :Sign.Sign;
}

struct CtrlPld {
    union {
        unset @0 :Void;
        pcb @1 :Void;
        pathMgmt @2 :Void;
        sibra @3 :Void;
        drkeyMgmt @4 :DRKeyMgmt.DRKeyMgmt;
        sig @5 :Void;
        ack @6 :Void;
    }
    reqId @7 :UInt64;
    traceId @8 :Data;
}
