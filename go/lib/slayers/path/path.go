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

package path

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/serrors"
)

// PathType is uint8 so 256 values max.
const maxPathType = 256

var registeredPaths [maxPathType]metadata

// Type indicates the type of the path contained in the SCION header.
type Type uint8

func (t Type) String() string {
	pm := registeredPaths[t]
	if !pm.inUse {
		return fmt.Sprintf("UNKNOWN (%d)", t)
	}
	return fmt.Sprintf("%v (%d)", pm.Desc, t)
}

// Path is the path contained in the SCION header.
type Path interface {
	// SerializeTo serializes the path into the provided buffer.
	SerializeTo(b []byte) error
	// DecodesFromBytes decodes the path from the provided buffer.
	DecodeFromBytes(b []byte) error
	// Reverse reverses a path such that it can be used in the reversed direction.
	//
	// XXX(shitz): This method should possibly be moved to a higher-level path manipulation package.
	Reverse() (Path, error)
	// Len returns the length of a path in bytes.
	Len() int
	// Type returns the type of a path.
	Type() Type
}

type metadata struct {
	inUse bool
	Metadata
}

// Metadata defines a new SCION path type, used for dynamic SICON path type registration.
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
func RegisterPath(pathMeta Metadata) {
	pm := registeredPaths[pathMeta.Type]
	if pm.inUse {
		panic("path type already registered")
	}
	registeredPaths[pathMeta.Type].inUse = true
	registeredPaths[pathMeta.Type].Metadata = pathMeta
}

// NewPath returns a new path object of pathType.
func NewPath(pathType Type) (Path, error) {
	pm := registeredPaths[pathType]
	if !pm.inUse {
		return nil, serrors.New("unsupported path", "type", pathType)
	}
	return pm.New(), nil
}
