@0xe6c88f91b6a1209e;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct RoutingPolicyExt{
    polType @0 :UInt8;  # The policy type
    itf @1 :UInt64;
    isdases @2 :List(UInt32);
}