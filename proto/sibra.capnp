@0xd7ac72be29310d11;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct SibraPCBExt {
    id @0 :Data;
    info @1 :Data;
    up @2 :Bool;
    sofs @3 :List(Data);
}

struct SibraPayload {
}
