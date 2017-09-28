/*
Package proto contains mostly auto-generated code for parsing/packing SCION
capnp messages, as well as some helper functions to working with capnp in Go
simpler.

The helper functions are all contained in cereal.go. They provide a simple
interface to read/write any capnp messages that have a Go representation,
relying on https://godoc.org/zombiezen.com/go/capnproto2/pogs to do the
heavy lifting.

One thing to note is that these helper functions generally only operate on
complete capnp messages. If you, for example, want to create an IFID proto,
that needs to be nested inside a SCION control message. For example:

	// Create new ifid instance
	ifid1 := &ifid.IFID{OrigIfID: uint64(ifID)}
	// Wrap it in a SCION control message.
	cpld1, _ := ctrl.NewPld(ifid1)
	// Pack the ctrl message to bytes.
	b, _ := PackRoot(cpld1)
	// Parse new ctrl message from bytes.
	cpld2, _ := ParseFromRaw(b)
	// Access the contents (unnamed union).
	cont, _ := cpld2.Contents()
	// Interface-assertion to IFID type.
	ifid2 := cont.(*ifid.IFID)
*/
package proto
