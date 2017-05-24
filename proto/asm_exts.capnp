@0xe6c88f91b6a1209e;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct RoutingPolicyExt{
    polType @0 :UInt8;  # The policy type
    ifID @1 :UInt64;
    isdases @2 :List(UInt32);
}

struct ISDAnnouncementExt{
    test @0 :UInt8; # TODO(Sezer): implement this
}

struct ASMExt {
    extension :union {
        routingPolicy @0 :RoutingPolicyExt;
        isdAnnouncement @1 :ISDAnnouncementExt; # TODO(Sezer): implement this
    }
}
