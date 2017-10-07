@0x8273379c3e06a721;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

using Sciond = import "sciond.capnp";

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
    ctrl @0 :Sciond.HostInfo;
    encapPort @1 :UInt16;
}
