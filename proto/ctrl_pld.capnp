@0xdf42b02816bdc1bf;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

using PCB = import "pcb.capnp";
using Sign = import "sign.capnp";
using CertMgmt = import "cert_mgmt.capnp";
using IFID = import "ifid.capnp";
using PathMgmt = import "path_mgmt.capnp";
using SIBRA = import "sibra.capnp";
using DRKeyMgmt = import "drkey_mgmt.capnp";
using SIG = import "sig.capnp";
using CtrlExtn = import "ctrl_extn.capnp";

struct SignedCtrlPld {
    blob @0 :Data;  # Raw CtrlPld
    sign @1 :Sign.Sign;
}

struct CtrlPld {
    union {
        unset @0 :Void;
        pcb @1 :PCB.PathSegment;
        ifid @2 :IFID.IFID;
        certMgmt @3 :CertMgmt.CertMgmt;
        pathMgmt @4 :PathMgmt.PathMgmt;
        sibra @5 :SIBRA.SibraPayload;
        drkeyMgmt @6 :DRKeyMgmt.DRKeyMgmt;
        sig @7 :SIG.SIGCtrl;
        extn @8 :CtrlExtn.CtrlExtnDataList;
    }
}
