@0xe6c88f91b6a1209e;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct RoutingPolicyExt{
    extType @0 :UInt8;  # The extension type
    polType @1 :UInt8;  # The policy type
    itf @2 :UInt64;
    isdases @3 :List(UInt32);
}