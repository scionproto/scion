@0xe6d9e9e231c09f51;

using RevInfo = import "rev_info.capnp";

struct Info {
    ifID @0 :UInt16;
    active @1 :Bool;
    revInfo @2 :RevInfo.RevInfo;
}

struct Infos {
    infos @0 :List(Info);
}

struct Req {
    ifID @0 :UInt16;
}
