@0xdd2455af722e4379
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

using RevInfo = import "rev_info.capnp";

struct SCIONDMsg {
    :union {
        unset @0 :Void;
        pathReq @1 :PathReq;
        pathReply @2 :PathReply;
        asReq @3 :ASReq;
        asReply @4 :ASReply;
        revInfo @5 :RevInfo.RevInfo
    }
}

struct PathReq {
    dst @0 :UInt32;  # Destination ISD-AS
    src @1 :UInt32;  # Source ISD-AS
    flags :group {
        flush @2 :Bool;  # Flush all paths to dst.
        sibra @3 :Bool;  # True, if SIBRA paths are requested
    }
}

struct PathReply {
    entries @0 :List(PathReplyEntry)
}

struct PathReplyEntry {
    path @0 :SCIONPath;  # End2end path
    port @1 :UInt16;  # First hop port
    addrs :group {  # First hop address
        ipv4 @2 :Data;
        ipv6 @3 :Data;
    }
}

struct SCIONPath {
    fields @0 :Data;  # The info- and hopfields of the path
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
