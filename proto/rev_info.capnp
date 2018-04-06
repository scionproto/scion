@0xc434abcc856ab808;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct RevInfo {
	ifID @0 :UInt64;  # ID of the interface to be revoked
	isdas @1 :UInt64;  # ISD-AS of the revocation issuer.
	linkType @2 :LinkType;  # Link type of the revoked interface
	timestamp @3 :UInt64;  # Creation timestamp, seconds since Unix Epoch
}

enum LinkType {
    core @0;
    parent @1;
    child @2;
    peer @3;
}
