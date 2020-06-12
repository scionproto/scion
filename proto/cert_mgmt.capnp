@0xec3b2b10a5e23975;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

using Sign = import "sign.capnp";

struct CertChainReq {
    isdas @0 :UInt64;
    subjectKeyID @1 :Data;
    date @2 :Int64;
}

struct CertChain {
    # Chains contains a list of byte-stitched (AS and CA cert appended without
    # special indicator) x509 chains containing AS and CA cert.
    chains @0 :List(Data);
}

struct CertChainRenewalRequest {
    # CSR is the x509 CSR.
    csr @0 :Data;
    sign @1 :Sign.Sign;
}

struct CertChainRenewalReply {
    # Chain is byte-stitched (AS and CA cert appended without special indicator)
    # x509 chain containing AS and CA cert.
    chain @0 :Data;
    sign @1 :Sign.Sign;
}

struct TRCReq {
    isd @0 :UInt16;
    base @1 :UInt64;
    serial @2 :UInt64;
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
        certChainRenewalRequest @5 :CertChainRenewalRequest;
        certChainRenewalReply @6 :CertChainRenewalReply;
    }
}
