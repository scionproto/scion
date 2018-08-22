@0x9cb1ca08a160c787;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct IFID {
   origIF @0 :UInt64;
}
