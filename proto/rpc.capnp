@0xd102d283500f3336;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct Request {
    id @0 :UInt64;
}

struct Reply {
    id @0 :UInt64;
}
