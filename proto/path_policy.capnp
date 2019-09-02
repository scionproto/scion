@0xe45bfd61f120454d;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct Policy {
    acl @0 :ACL;
    sequence @1 :Text;
    options @2 :List(Option);
}

struct ExtPolicy {
    extends @0 :List(Text);
    policy @1 :Policy;
}

struct Option {
    weight @0 :Int32;
    policy @1 :ExtPolicy;
}

struct ACL {
    entries @0 :List(ACLEntry);
}

struct ACLEntry {
    action @0 :ACLAction;
    rule @1 :HopPredicate;

}

struct HopPredicate {
    isdas @0 :UInt64;
    ifids @1 :List(UInt64);
}

enum ACLAction {
    unset @0;
    deny @1;
    allow @2;
}
