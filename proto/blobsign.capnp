@0x99440334ec0946a0;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct Blob {
    blob @0 :Data;
    sign @1 :Sign;
}

struct Sign {
    # Signature type. If this is `none`, then the rest of this struct should be ignored.
    type @0 :SigType;
    # Signature over blob, using signType, created by src. Unset if signType is `none`.
    signature @1 :Data;
    # Id (e.g. ISD-AS) of signer. Unset if signType is `none`.
    src @2 :Data;
}

enum SigType {
    none @0;
    ed25519 @1;
}
