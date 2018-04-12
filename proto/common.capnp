@0xfa01960eced2b529;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

enum LinkType {
    unset @0;
    core @1;
    parent @2;
    child @3;
    peer @4;
}
