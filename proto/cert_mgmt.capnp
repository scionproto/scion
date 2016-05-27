@0xec3b2b10a5e23975;

struct CertChainReq {
    isdas @0 :Text;
    version @1 :UInt32;
}

struct CertChainRep {
    chain @0 :Data;
}

struct TRCReq {
    isdas @0 :Text;
    version @1 :UInt32;
}

struct TRCRep {
    trc @0 :Data;
}
