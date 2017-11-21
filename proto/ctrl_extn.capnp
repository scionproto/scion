@0xfa3f5dec2b78a085;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct CtrlExtnDataList {
    items @0 :List(CtrlExtnData);
}

struct CtrlExtnData {
    type @0 :Data;
    data @1 :Data;
}
