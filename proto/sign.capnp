@0x99440334ec0946a0;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct SignedBlob {
    blob @0 :Data;
    sign @1 :Sign;
}

struct Sign {
    # Signature type. If this is `none`, then the rest of this struct should be ignored.
    type @0 :SignType;
    # Id (e.g. ISD-AS) of signer. Unset if signType is `none`.
    src @1 :Data;
    # Signature over blob, using signType, created by src. Unset if signType is `none`.
    signature @2 :Data;
}

enum SignType {
    none @0;
    ed25519 @1;
}
