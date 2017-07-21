@0x8b5294a99c97dcb6;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct SIGControl {
    union {
        unset @0 :Void;
        hello @1 :Hello;
    }
}

struct Hello {
    id @0 :UInt64;
}
