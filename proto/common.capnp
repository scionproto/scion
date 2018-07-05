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

enum ServiceType {
    bs @0;  # Beacon service
    ps @1;  # Path service
    cs @2;  # Certificate service
    sb @3;  # SIBRA service
}
