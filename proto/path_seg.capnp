@0xfb8053d9fb34b837;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

enum PathSegType {
    unset @0;
    up @1;
    down @2;
    core @3;
}
