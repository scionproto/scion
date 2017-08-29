@0xfb8730df4ba4809b;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct SetInfo {
    setID @0 :Data;
    hpsIA @1 :UInt32;
    memberIAs @2 :List(UInt32);
}
