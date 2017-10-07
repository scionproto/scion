@0x8273379c3e06a721;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

using Sciond = import "sciond.capnp";

struct SIGCtrl {
    union {
        unset @0 :Void;
        pollReq @1 :SIGPoll;
        pollRep @2 :SIGPoll;
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
