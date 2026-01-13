// Copyright 2020 Anapaya Systems
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

// +gobra

package path

import (
	"fmt"

	// @ "github.com/scionproto/scion/gobra/utils"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// PathType is uint8 so 256 values max.
const maxPathType = 256

var (
	registeredPaths/*@@@*/ [maxPathType]metadata
	strictDecoding/*@@@*/ bool = true
)

// Type indicates the type of the path contained in the SCION header.
type Type uint8

// @ requires 0 <= t && t < maxPathType
// @ preserves acc(PkgMem(), utils.ReadPerm)
// @ decreases
func (t Type) String() string {
	// @ unfold acc(PkgMem(), utils.ReadPerm)
	pm := registeredPaths[t]
	// @ fold acc(PkgMem(), utils.ReadPerm)
	if !pm.inUse {
		return fmt.Sprintf("UNKNOWN (%d)", t)
	}
	return fmt.Sprintf("%v (%d)", pm.Desc, t)
}

// Path is the path contained in the SCION header.
type Path interface {

	// Ownserhip of all necessary memory locations required to safely call
	// DecodeFromBytes() on a Path instance.
	//@ pred PreDecodeMem()

	// Ownserhip of all memory locations on an instance of Path initialized
	// via a call to DecodeFromBytes.
	//@ pred Mem()

	// Returns the slice of bytes from which the Path instance was decoded.
	// @ ghost
	// @ pure
	// @ requires Mem()
	// @ decreases
	// @ DecodedFrom() []byte

	// SerializeTo serializes the path into the provided buffer.
	// @ preserves acc(Mem(), utils.ReadPerm)
	// SerializeTo takes full ownership of the slice from which
	// the instance was decoded, which allows for that slice to
	// be mutated during the call to this method. This is perhaps
	// surpising; one may expect that that slice is only read.
	// However, the implementations of this method for type *Raw
	// (declared in pkg/slayers/scion) does mutate the slice.
	// @ preserves acc(utils.ByteSlice(DecodedFrom()))
	// @ preserves utils.ByteSlice(b)
	// @ ensures   err != nil ==> err.ErrorMem()
	SerializeTo(b []byte) (err error)

	// DecodesFromBytes decodes the path from the provided buffer.
	// @ requires  PreDecodeMem()
	// @ preserves acc(utils.ByteSlice(b), utils.ReadPerm)
	// @ ensures   err == nil ==> Mem() && DecodedFrom() === b
	// @ ensures   err != nil ==> err.ErrorMem() && PreDecodeMem()
	DecodeFromBytes(b []byte) (err error)

	// Reverse reverses a path such that it can be used in the reversed direction.
	//
	// XXX(shitz): This method should possibly be moved to a higher-level path manipulation package.
	// @ requires Mem()
	// @ requires acc(utils.ByteSlice(DecodedFrom()))
	// @ ensures  acc(utils.ByteSlice(old(DecodedFrom())))
	// @ ensures  err == nil ==>
	// @ 	p != nil && p.Mem() && p.DecodedFrom() === old(DecodedFrom())
	// @ ensures err != nil ==> err.ErrorMem()
	Reverse() (p Path, err error)

	// Len returns the length of a path in bytes.
	// @ preserves acc(Mem(), utils.ReadPerm)
	// @ ensures   0 <= res
	Len() (res int)

	// Type returns the type of a path.
	// @ preserves acc(Mem(), utils.ReadPerm)
	Type() Type
}

type metadata struct {
	inUse bool
	Metadata
}

// Metadata defines a new SCION path type, used for dynamic SCION path type registration.
type Metadata struct {
	// Type is a unique value for the path.
	Type Type
	// Desc is the description/name of the path.
	Desc string
	// New is a path constructor function.
	New func() Path
}

// RegisterPath registers a new SCION path type globally.
// The PathType passed in must be unique, or a runtime panic will occur.
// @ requires 0 <= pathMeta.Type && pathMeta.Type < maxPathType
// @ requires PkgMem() && !Registered(pathMeta.Type)
// @ requires pathMeta.New implements NewPathSpec
// @ ensures  PkgMem()
// @ decreases
func RegisterPath(pathMeta Metadata) {
	// @ unfold PkgMem()
	pm := registeredPaths[pathMeta.Type]
	if pm.inUse {
		panic("path type already registered: " + pathMeta.Type.String())
	}
	registeredPaths[pathMeta.Type].inUse = true
	registeredPaths[pathMeta.Type].Metadata = pathMeta
	// @ fold PkgMem()
}

// StrictDecoding enables or disables strict path decoding. If enabled, unknown
// path types fail to decode. If disabled, unknown path types are decoded into a
// raw path that keeps the encoded path around for re-serialization.
//
// Strict parsing is enabled by default.
//
// Experimental: This function is experimental and might be subject to change.
// @ preserves PkgMem()
// @ decreases
func StrictDecoding(strict bool) {
	// @ unfold PkgMem()
	strictDecoding = strict
	// @ fold PkgMem()
}

// NewPath returns a new path object of pathType.
// @ requires 0 <= pathType && pathType < maxPathType
// @ preserves acc(PkgMem(), utils.ReadPerm)
// @ decreases
func NewPath(pathType Type) (Path, error) {
	// @ unfold  acc(PkgMem(), utils.ReadPerm)
	// @ defer fold  acc(PkgMem(), utils.ReadPerm)
	pm := registeredPaths[pathType]
	if !pm.inUse {
		if strictDecoding {
			return nil, serrors.New("unsupported path", "type", pathType)
		}
		return &rawPath{}, nil
	}
	return pm.New() /*@ as NewPathSpec @*/, nil
}

// NewRawPath returns a new raw path that can hold any path type.
// @ ensures res.PreDecodeMem()
// @ decreases
func NewRawPath() (res Path) {
	p := &rawPath{}
	// @ fold p.PreDecodeMem()
	return p
}

type rawPath struct {
	raw      []byte
	pathType Type
}

// @ preserves acc(p.Mem(), utils.ReadPerm)
// @ preserves acc(utils.ByteSlice(p.DecodedFrom()), utils.ReadPerm)
// @ preserves utils.ByteSlice(b)
// @ ensures   p.DecodedFrom() === old(p.DecodedFrom())
// @ ensures   err != nil ==> err.ErrorMem()
// @ decreases
func (p *rawPath) SerializeTo(b []byte) (err error) {
	// @ ghost buf := p.DecodedFrom()
	// @ unfold acc(p.Mem(), utils.ReadPerm)
	// @ assert buf === p.raw

	// @ unfold utils.ByteSlice(b)
	// @ unfold acc(utils.ByteSlice(p.raw), utils.ReadPerm)
	copy(b, p.raw /*@, utils.ReadPerm @*/)
	// @ fold acc(utils.ByteSlice(p.raw), utils.ReadPerm)
	// @ fold utils.ByteSlice(b)
	// @ fold acc(p.Mem(), utils.ReadPerm)
	return nil
}

// @ requires  p.PreDecodeMem()
// @ ensures   err == nil && p.Mem() && p.DecodedFrom() === b
// @ decreases
func (p *rawPath) DecodeFromBytes(b []byte) (err error) {
	// @ unfold p.PreDecodeMem()
	p.raw = b
	// @ fold p.Mem()
	return nil
}

// @ ensures err != nil && err.ErrorMem()
// @ decreases
func (p *rawPath) Reverse() (res Path, err error) {
	return nil, serrors.New("not supported")
}

// @ preserves acc(p.Mem(), utils.ReadPerm)
// @ ensures   0 <= res
// @ decreases
func (p *rawPath) Len() (res int) {
	// @ unfold acc(p.Mem(), utils.ReadPerm)
	// @ defer fold acc(p.Mem(), utils.ReadPerm)
	return len(p.raw)
}

// @ preserves acc(p.Mem(), utils.ReadPerm)
// @ decreases
func (p *rawPath) Type() Type {
	// @ unfold acc(p.Mem(), utils.ReadPerm)
	// @ defer fold acc(p.Mem(), utils.ReadPerm)
	return p.pathType
}
