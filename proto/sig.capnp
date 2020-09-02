@0x8273379c3e06a721;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct HostInfo {
    port @0 :UInt16;  # Reachable port of the host.
    addrs :group {  # Addresses of the host.
        ipv4 @1 :Data;
        ipv6 @2 :Data;
    }
}

struct SIGCtrl {
    id @0 :UInt64;
    union {
        unset @1 :Void;
        pollReq @2 :SIGPoll;
        pollRep @3 :SIGPoll;
    }
}

struct SIGPoll {
    addr @0 :SIGAddr;
    session @1 :UInt8;
}

struct SIGAddr {
    ctrl @0 :HostInfo;
    data @1 :HostInfo;
}
