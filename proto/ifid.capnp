@0x9cb1ca08a160c787;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

# IFID is the ifid keepalive message sent between beacon servers.
struct IFID {
   origIF @0 :UInt64;  # The egress interface a keepalive was sent on.
}
