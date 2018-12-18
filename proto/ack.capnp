@0xc736b44d517db44a;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct Ack {
    err @0 :ErrCode;
    errDesc @1 :Text;

    enum ErrCode {
        ok @0;
        retry @1;
        reject @2;
    }
}
