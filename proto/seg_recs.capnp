@0xe96004446ccd70e0;

struct SegRecs {
    pcbs @0 :List(RawPCB);

    struct RawPCB {
        type @0 :UInt8;
        raw @1 :Data;
    }
}
