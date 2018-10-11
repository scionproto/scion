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
    unset @0; # Not set
    bs @1;  # Beacon service
    ps @2;  # Path service
    cs @3;  # Certificate service
    sb @4;  # SIBRA service
    ds @5;  # Discovery service
    br @6;  # Border router
}
