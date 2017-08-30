@0x9cb1ca08a160c787;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct IFID {
   origIF @0 :UInt64;
   relayIF @1 :UInt64;
}
