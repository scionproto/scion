@0xdf42b02816bdc1bf;

using PCB = import "pcb.capnp";
using CertMgmt = import "cert_mgmt.capnp";
using IFID = import "ifid.capnp";
using PathMgmt = import "path_mgmt.capnp";
using SIBRA = import "sibra.capnp";

struct SCION {
    union {
        unset @0 :Void;
        pcb @1 :PCB.PathSegment;
        ifid @2 :IFID.IFID;
        certMgmt @3 :CertMgmt.CertMgmt;
        pathMgmt @4 :PathMgmt.PathMgmt;
        sibra @5 :SIBRA.SibraPayload;
    }
}
