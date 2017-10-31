@0xdf42b02816bdc1bf;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

using Blob = import "blobsign.capnp";
using PSeg = import "pathseg.capnp";
using CertMgmt = import "cert_mgmt.capnp";
using IFID = import "ifid.capnp";
using PathMgmt = import "path_mgmt.capnp";
using SIBRA = import "sibra.capnp";
using DRKeyMgmt = import "drkey_mgmt.capnp";
using SIG = import "sig.capnp";

struct CtrlPld {
    blob @0 :Data;  # Raw CtrlPldUnion
    sign @1 :Blob.Sign;
}

struct CtrlPldUnion {
    union {
        unset @0 :Void;
        pcb @1 :PSeg.PCB;
        pSeg @2 :PSeg.PathSegment;
        ifid @3 :IFID.IFID;
        certMgmt @4 :CertMgmt.CertMgmt;
        pathMgmt @5 :PathMgmt.PathMgmt;
        sibra @6 :SIBRA.SibraPayload;
        drkeyMgmt @7 :DRKeyMgmt.DRKeyMgmt;
        sig @8 :SIG.SIGCtrl;
    }
}
