@0xec3b2b10a5e23975;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct CertChainReq {
    isdas @0 :UInt32;
    version @1 :UInt64;
    cacheOnly @2 :Bool;
}

struct CertChain {
    chain @0 :Data;
}

struct CertChainIssReq {
    cert @0 :Data;        # Raw Certificate with desired values
}

struct CertChainIssRep {
    chain @0 :Data;
}

struct TRCReq {
    isd @0 :UInt16;
    version @1 :UInt64;
    cacheOnly @2 :Bool;
}

struct TRC {
    trc @0 :Data;
}

struct CertMgmt {
    union {
        unset @0 :Void;
        certChainReq @1 :CertChainReq;
        certChain @2 :CertChain;
        trcReq @3 :TRCReq;
        trc @4 :TRC;
        certChainIssReq @5 :CertChainIssReq;
        certChainIssRep @6 :CertChainIssRep;
    }
}
