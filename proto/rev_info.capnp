@0xc434abcc856ab808;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

using Common = import "common.capnp";

struct RevInfo {
    ifID @0 :UInt64;               # ID of the interface to be revoked
    isdas @1 :UInt64;              # ISD-AS of the revocation issuer.
    linkType @2 :Common.LinkType;  # Link type of the revoked interface
    timestamp @3 :UInt32;          # Creation timestamp, seconds since Unix Epoch
    ttl @4 :UInt32;                # The validity period of the revocation in seconds.
}
