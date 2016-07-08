@0xc4f0db62ff503b7d;

struct ZkId {
    isdas @0 :Text;
    id @1 :Text;
    addrs @2 :List(Addr);
}

struct Addr {
    type @0 :UInt8;
    addr @1 :Data;
    port @2 :UInt16;
}
