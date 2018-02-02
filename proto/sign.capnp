@0x99440334ec0946a0;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

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
    # Signature creation time. Seconds since Unix Epoch.
    timestamp @3 :UInt64;
}

# Default structure for Sign.src
struct SignSrc {
    # ISD-AS of signer
    isdas @0 :UInt32;
    # Version of certificate chain authenticating signature
    chainVersion @1 :UInt64;
    # Version of TRC authenticating certificate chain
    trcVersion @2 :UInt64;
}

enum SignType {
    none @0;
    ed25519 @1;
}
