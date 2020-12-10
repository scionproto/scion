// Copyright 2017 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
