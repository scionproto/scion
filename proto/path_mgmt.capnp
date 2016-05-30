@0x8fcd13516850d142;

struct SegReq {
    srcIA @0 :Text;
    dstIA @1 :Text;
    flags :group {
        sibra @2 :Bool;
    }
}

struct SegRecs {
    pcbs @0 :List(RawPCB);

    struct RawPCB {
        type @0 :UInt8;
        raw @1 :Data;
    }
}
