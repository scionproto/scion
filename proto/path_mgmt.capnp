@0x8fcd13516850d142;

using PCB = import "pcb.capnp";

struct SegReq {
    srcIA @0 :Text;
    dstIA @1 :Text;
    flags :group {
        sibra @2 :Bool;
    }
}

struct SegRecs {
    recs @0 :List(PCB.PathSegMeta);
}
