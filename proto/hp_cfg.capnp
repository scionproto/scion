@0xfb570d9dd09c7fb7;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct HPCfgId {
    masterIA @0 :Data;
    cfgId @1 :UInt64;
}

struct HPCfg {
    id @0 :HPCfgId;
    version @1: UInt64;
    hpsIAs @2 :List(Data);  # ISD_AS of hidden path servers that stores hidden paths
    writerIAs @3 :List(Data);  # ISD_AS of ASes that are authorized to register hidden paths
    readerIAs @4 :List(Data);  # ISD_AS of ASes authorized to use the hidden paths
}