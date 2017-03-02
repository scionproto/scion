@0x8f4bd412642c9517;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

using RevInfo = import "rev_info.capnp";

struct SCIONDMsg {
    union {
        unset @0 :Void;
        pathReq @1 :PathReq;
        pathReply @2 :PathReply;
        asReq @3 :ASReq;
        asReply @4 :ASReply;
        revInfo @5 :RevInfo.RevInfo;
    }
}

struct PathReq {
    id @0 :UInt64;  # Request ID
    dst @1 :UInt32;  # Destination ISD-AS
    src @2 :UInt32 = 0;  # Source ISD-AS
    maxPaths @3: UInt16;  # Maximum number of paths requested
    flags :group {
        flush @4 :Bool;  # Flush all paths to dst.
        sibra @5 :Bool;  # True, if SIBRA paths are requested
    }
}

struct PathReply {
    id @0 :UInt64;  # Response ID (matches the request ID)
    errorCode @1 :UInt16;
    entries @2 :List(PathReplyEntry);
}

struct PathReplyEntry {
    path @0 :FwdPathMeta;  # End2end path
    port @1 :UInt16;  # First hop port
    addrs :group {  # First hop address
        ipv4 @2 :Data;
        ipv6 @3 :Data;
    }
}

struct FwdPathMeta {
    fwdPath @0 :Data;  # The info- and hopfields of the path
    mtu @1 :UInt16;
    interfaces @2 :List(PathInterface);
}

struct PathInterface {
    isdas @0 :UInt32;
    ifID @1 :UInt8;
}

struct ASReq {
}

struct ASReply {
    ases @0 :List(UInt32);  # List of ASes the host is part of
}
