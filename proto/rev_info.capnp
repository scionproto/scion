@0xc434abcc856ab808;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct SiblingHash {
	isLeft @0 :Bool;  # Is the sibling on the left?
	hash @1 :Data;  # Hash Value of the sibling
}

struct RevInfo {
	ifID @0 :UInt64;  # ID of the interface to be revoked
	epoch @1 :UInt64;  # Epoch for which interface is to be revoked
	nonce @2 :Data;  # Nonce corresponding to the (ifID,epoch) leaf in hashtree
	siblings @3 :List(SiblingHash);  # Hash values of siblings, bottom to top
	prevRoot @4 :Data;  # Root of the hashtree of previous time block (T-1)
	nextRoot @5 :Data;  # Root of the hashtree of next time block (T+1)
	isdas @6 :UInt32;  # ISD-AS of the revocation issuer.
	hashType @7 :UInt16;  # The hash function type needed to verify the revocation.
	treeTTL @8 :UInt32;  # The validity period of the revocation tree.
}
